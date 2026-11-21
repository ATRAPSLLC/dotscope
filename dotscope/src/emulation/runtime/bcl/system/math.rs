//! `System.Math` and `System.Numerics.BitOperations` method hooks.
//!
//! This module provides hook implementations for mathematical operations commonly used
//! in obfuscation for numeric transformations, control flow flattening state machines,
//! and hash computations.
//!
//! # Overview
//!
//! Mathematical operations are fundamental to many obfuscation techniques:
//! - **Control flow flattening**: Uses arithmetic to compute switch cases
//! - **Opaque predicates**: Complex math expressions that always evaluate to known values
//! - **Bit manipulation**: `BitOperations` for XOR-based encryption state
//!
//! # Hooked .NET Methods
//!
//! ## Basic Math
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Math.Abs(x)` | Absolute value |
//! | `Math.Min(a, b)` | Minimum of two values |
//! | `Math.Max(a, b)` | Maximum of two values |
//! | `Math.Sign(x)` | Returns -1, 0, or 1 |
//! | `Math.Clamp(val, min, max)` | Constrains value to range |
//! | `Math.DivRem(a, b)` | Division with remainder |
//!
//! ## Rounding
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Math.Floor(x)` | Round down |
//! | `Math.Ceiling(x)` | Round up |
//! | `Math.Round(x, [decimals])` | Round to nearest |
//! | `Math.Truncate(x)` | Remove fractional part |
//!
//! ## Power and Logarithms
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Math.Pow(x, y)` | x raised to power y |
//! | `Math.Sqrt(x)` | Square root |
//! | `Math.Log(x, [base])` | Natural or custom base log |
//! | `Math.Log10(x)` | Base-10 logarithm |
//! | `Math.Exp(x)` | e raised to power x |
//!
//! ## Trigonometry
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Math.Sin`, `Cos`, `Tan` | Basic trigonometric functions |
//! | `Math.Asin`, `Acos`, `Atan` | Inverse trigonometric functions |
//! | `Math.Atan2(y, x)` | Two-argument arctangent |
//!
//! ## BitOperations (System.Numerics)
//!
//! | Method | Description |
//! |--------|-------------|
//! | `PopCount(x)` | Count set bits |
//! | `LeadingZeroCount(x)` | Leading zero bits |
//! | `TrailingZeroCount(x)` | Trailing zero bits |
//! | `RotateLeft(x, n)` | Rotate bits left |
//! | `RotateRight(x, n)` | Rotate bits right |
//!
//! # Deobfuscation Use Cases
//!
//! ## Control Flow Flattening
//!
//! ```csharp
//! int state = initialState;
//! while (true) {
//!     switch (state) {
//!         case 0: state = Math.Abs(x - 5); break;  // Computed dispatch
//!         // ...
//!     }
//! }
//! ```
//!
//! ## XOR Key Derivation
//!
//! ```csharp
//! int key = BitOperations.RotateLeft(seed, 13);
//! key ^= BitOperations.PopCount(magic);
//! ```

use crate::{
    emulation::{
        engine::synthetic_exception,
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        EmValue,
    },
    metadata::typesystem::CilFlavor,
    Result,
};

/// Registers all `System.Math` and `BitOperations` method hooks.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
///
/// # Registered Methods
///
/// - **Basic**: `Abs`, `Min`, `Max`, `Sign`, `Clamp`, `DivRem`
/// - **Rounding**: `Floor`, `Ceiling`, `Round`, `Truncate`
/// - **Power/Log**: `Pow`, `Sqrt`, `Log`, `Log10`, `Exp`
/// - **Trig**: `Sin`, `Cos`, `Tan`, `Asin`, `Acos`, `Atan`, `Atan2`
/// - **BitOps**: `PopCount`, `LeadingZeroCount`, `TrailingZeroCount`, `RotateLeft`, `RotateRight`
pub fn register(manager: &HookManager) -> Result<()> {
    // Basic math
    manager.register(
        Hook::new("System.Math.Abs")
            .match_name("System", "Math", "Abs")
            .pre(system_math_abs_pre),
    )?;
    manager.register(
        Hook::new("System.Math.Min")
            .match_name("System", "Math", "Min")
            .pre(system_math_min_pre),
    )?;
    manager.register(
        Hook::new("System.Math.Max")
            .match_name("System", "Math", "Max")
            .pre(system_math_max_pre),
    )?;
    manager.register(
        Hook::new("System.Math.Sign")
            .match_name("System", "Math", "Sign")
            .pre(system_math_sign_pre),
    )?;
    manager.register(
        Hook::new("System.Math.Clamp")
            .match_name("System", "Math", "Clamp")
            .pre(system_math_clamp_pre),
    )?;
    manager.register(
        Hook::new("System.Math.DivRem")
            .match_name("System", "Math", "DivRem")
            .pre(system_math_divrem_pre),
    )?;

    // Rounding
    manager.register(
        Hook::new("System.Math.Floor")
            .match_name("System", "Math", "Floor")
            .pre(system_math_floor_pre),
    )?;
    manager.register(
        Hook::new("System.Math.Ceiling")
            .match_name("System", "Math", "Ceiling")
            .pre(system_math_ceiling_pre),
    )?;
    manager.register(
        Hook::new("System.Math.Round")
            .match_name("System", "Math", "Round")
            .pre(system_math_round_pre),
    )?;
    manager.register(
        Hook::new("System.Math.Truncate")
            .match_name("System", "Math", "Truncate")
            .pre(system_math_truncate_pre),
    )?;

    // Power/Log
    manager.register(
        Hook::new("System.Math.Pow")
            .match_name("System", "Math", "Pow")
            .pre(system_math_pow_pre),
    )?;
    manager.register(
        Hook::new("System.Math.Sqrt")
            .match_name("System", "Math", "Sqrt")
            .pre(system_math_sqrt_pre),
    )?;
    manager.register(
        Hook::new("System.Math.Log")
            .match_name("System", "Math", "Log")
            .pre(system_math_log_pre),
    )?;
    manager.register(
        Hook::new("System.Math.Log10")
            .match_name("System", "Math", "Log10")
            .pre(system_math_log10_pre),
    )?;
    manager.register(
        Hook::new("System.Math.Exp")
            .match_name("System", "Math", "Exp")
            .pre(system_math_exp_pre),
    )?;

    // Trigonometry
    manager.register(
        Hook::new("System.Math.Sin")
            .match_name("System", "Math", "Sin")
            .pre(system_math_sin_pre),
    )?;
    manager.register(
        Hook::new("System.Math.Cos")
            .match_name("System", "Math", "Cos")
            .pre(system_math_cos_pre),
    )?;
    manager.register(
        Hook::new("System.Math.Tan")
            .match_name("System", "Math", "Tan")
            .pre(system_math_tan_pre),
    )?;
    manager.register(
        Hook::new("System.Math.Asin")
            .match_name("System", "Math", "Asin")
            .pre(system_math_asin_pre),
    )?;
    manager.register(
        Hook::new("System.Math.Acos")
            .match_name("System", "Math", "Acos")
            .pre(system_math_acos_pre),
    )?;
    manager.register(
        Hook::new("System.Math.Atan")
            .match_name("System", "Math", "Atan")
            .pre(system_math_atan_pre),
    )?;
    manager.register(
        Hook::new("System.Math.Atan2")
            .match_name("System", "Math", "Atan2")
            .pre(system_math_atan2_pre),
    )?;

    // Log2
    manager.register(
        Hook::new("System.Math.Log2")
            .match_name("System", "Math", "Log2")
            .pre(system_math_log2_pre),
    )?;

    // MathF — single-precision math
    manager.register(
        Hook::new("System.MathF.Abs")
            .match_name("System", "MathF", "Abs")
            .pre(system_mathf_abs_pre),
    )?;
    manager.register(
        Hook::new("System.MathF.Sin")
            .match_name("System", "MathF", "Sin")
            .pre(system_mathf_sin_pre),
    )?;
    manager.register(
        Hook::new("System.MathF.Cos")
            .match_name("System", "MathF", "Cos")
            .pre(system_mathf_cos_pre),
    )?;
    manager.register(
        Hook::new("System.MathF.Sqrt")
            .match_name("System", "MathF", "Sqrt")
            .pre(system_mathf_sqrt_pre),
    )?;
    manager.register(
        Hook::new("System.MathF.Floor")
            .match_name("System", "MathF", "Floor")
            .pre(system_mathf_floor_pre),
    )?;
    manager.register(
        Hook::new("System.MathF.Ceiling")
            .match_name("System", "MathF", "Ceiling")
            .pre(system_mathf_ceiling_pre),
    )?;
    manager.register(
        Hook::new("System.MathF.Round")
            .match_name("System", "MathF", "Round")
            .pre(system_mathf_round_pre),
    )?;
    manager.register(
        Hook::new("System.MathF.Min")
            .match_name("System", "MathF", "Min")
            .pre(system_mathf_min_pre),
    )?;
    manager.register(
        Hook::new("System.MathF.Max")
            .match_name("System", "MathF", "Max")
            .pre(system_mathf_max_pre),
    )?;
    manager.register(
        Hook::new("System.MathF.Pow")
            .match_name("System", "MathF", "Pow")
            .pre(system_mathf_pow_pre),
    )?;
    manager.register(
        Hook::new("System.MathF.Log")
            .match_name("System", "MathF", "Log")
            .pre(system_mathf_log_pre),
    )?;
    manager.register(
        Hook::new("System.MathF.Log2")
            .match_name("System", "MathF", "Log2")
            .pre(system_mathf_log2_pre),
    )?;
    manager.register(
        Hook::new("System.MathF.Log10")
            .match_name("System", "MathF", "Log10")
            .pre(system_mathf_log10_pre),
    )?;
    manager.register(
        Hook::new("System.MathF.Tan")
            .match_name("System", "MathF", "Tan")
            .pre(system_mathf_tan_pre),
    )?;
    manager.register(
        Hook::new("System.MathF.Asin")
            .match_name("System", "MathF", "Asin")
            .pre(system_mathf_asin_pre),
    )?;
    manager.register(
        Hook::new("System.MathF.Acos")
            .match_name("System", "MathF", "Acos")
            .pre(system_mathf_acos_pre),
    )?;
    manager.register(
        Hook::new("System.MathF.Atan")
            .match_name("System", "MathF", "Atan")
            .pre(system_mathf_atan_pre),
    )?;
    manager.register(
        Hook::new("System.MathF.Atan2")
            .match_name("System", "MathF", "Atan2")
            .pre(system_mathf_atan2_pre),
    )?;
    manager.register(
        Hook::new("System.MathF.Exp")
            .match_name("System", "MathF", "Exp")
            .pre(system_mathf_exp_pre),
    )?;
    manager.register(
        Hook::new("System.MathF.Truncate")
            .match_name("System", "MathF", "Truncate")
            .pre(system_mathf_truncate_pre),
    )?;
    manager.register(
        Hook::new("System.MathF.Sign")
            .match_name("System", "MathF", "Sign")
            .pre(system_mathf_sign_pre),
    )?;

    // BitOperations
    manager.register(
        Hook::new("System.Numerics.BitOperations.PopCount")
            .match_name("System.Numerics", "BitOperations", "PopCount")
            .pre(system_numerics_bitoperations_popcount_pre),
    )?;
    manager.register(
        Hook::new("System.Numerics.BitOperations.LeadingZeroCount")
            .match_name("System.Numerics", "BitOperations", "LeadingZeroCount")
            .pre(system_numerics_bitoperations_leadingzerocount_pre),
    )?;
    manager.register(
        Hook::new("System.Numerics.BitOperations.TrailingZeroCount")
            .match_name("System.Numerics", "BitOperations", "TrailingZeroCount")
            .pre(system_numerics_bitoperations_trailingzerocount_pre),
    )?;
    manager.register(
        Hook::new("System.Numerics.BitOperations.RotateLeft")
            .match_name("System.Numerics", "BitOperations", "RotateLeft")
            .pre(system_numerics_bitoperations_rotateleft_pre),
    )?;
    manager.register(
        Hook::new("System.Numerics.BitOperations.RotateRight")
            .match_name("System.Numerics", "BitOperations", "RotateRight")
            .pre(system_numerics_bitoperations_rotateright_pre),
    )?;
    Ok(())
}

/// Hook for `System.Math.Abs` method.
///
/// Returns the absolute value of a number.
///
/// # Handled Overloads
///
/// - `Math.Abs(SByte) -> SByte`
/// - `Math.Abs(Int16) -> Int16`
/// - `Math.Abs(Int32) -> Int32`
/// - `Math.Abs(Int64) -> Int64`
/// - `Math.Abs(Single) -> Single`
/// - `Math.Abs(Double) -> Double`
/// - `Math.Abs(Decimal) -> Decimal`
///
/// # Parameters
///
/// - `value`: The number whose absolute value is to be found
fn system_math_abs_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(0_i32.into()));
    };

    let result = match arg0 {
        EmValue::I32(n) => n.abs().into(),
        EmValue::I64(n) => n.abs().into(),
        EmValue::F32(f) => f.abs().into(),
        EmValue::F64(f) => f.abs().into(),
        _ => 0_i32.into(),
    };

    PreHookResult::Bypass(Some(result))
}

/// Hook for `System.Math.Min` method.
///
/// Returns the smaller of two numbers.
///
/// # Handled Overloads
///
/// - `Math.Min(SByte, SByte) -> SByte`
/// - `Math.Min(Byte, Byte) -> Byte`
/// - `Math.Min(Int16, Int16) -> Int16`
/// - `Math.Min(UInt16, UInt16) -> UInt16`
/// - `Math.Min(Int32, Int32) -> Int32`
/// - `Math.Min(UInt32, UInt32) -> UInt32`
/// - `Math.Min(Int64, Int64) -> Int64`
/// - `Math.Min(UInt64, UInt64) -> UInt64`
/// - `Math.Min(Single, Single) -> Single`
/// - `Math.Min(Double, Double) -> Double`
/// - `Math.Min(Decimal, Decimal) -> Decimal`
///
/// # Parameters
///
/// - `val1`: The first of two values to compare
/// - `val2`: The second of two values to compare
fn system_math_min_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let (Some(arg0), Some(arg1)) = (ctx.args.first(), ctx.args.get(1)) else {
        return PreHookResult::Bypass(ctx.args.first().cloned());
    };

    let result = match (arg0, arg1) {
        (EmValue::I32(a), EmValue::I32(b)) => (*a.min(b)).into(),
        (EmValue::I64(a), EmValue::I64(b)) => (*a.min(b)).into(),
        (EmValue::F32(a), EmValue::F32(b)) => a.min(*b).into(),
        (EmValue::F64(a), EmValue::F64(b)) => a.min(*b).into(),
        _ => arg0.clone(),
    };

    PreHookResult::Bypass(Some(result))
}

/// Hook for `System.Math.Max` method.
///
/// Returns the larger of two numbers.
///
/// # Handled Overloads
///
/// - `Math.Max(SByte, SByte) -> SByte`
/// - `Math.Max(Byte, Byte) -> Byte`
/// - `Math.Max(Int16, Int16) -> Int16`
/// - `Math.Max(UInt16, UInt16) -> UInt16`
/// - `Math.Max(Int32, Int32) -> Int32`
/// - `Math.Max(UInt32, UInt32) -> UInt32`
/// - `Math.Max(Int64, Int64) -> Int64`
/// - `Math.Max(UInt64, UInt64) -> UInt64`
/// - `Math.Max(Single, Single) -> Single`
/// - `Math.Max(Double, Double) -> Double`
/// - `Math.Max(Decimal, Decimal) -> Decimal`
///
/// # Parameters
///
/// - `val1`: The first of two values to compare
/// - `val2`: The second of two values to compare
fn system_math_max_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let (Some(arg0), Some(arg1)) = (ctx.args.first(), ctx.args.get(1)) else {
        return PreHookResult::Bypass(ctx.args.first().cloned());
    };

    let result = match (arg0, arg1) {
        (EmValue::I32(a), EmValue::I32(b)) => EmValue::I32(*a.max(b)),
        (EmValue::I64(a), EmValue::I64(b)) => EmValue::I64(*a.max(b)),
        (EmValue::F32(a), EmValue::F32(b)) => EmValue::F32(a.max(*b)),
        (EmValue::F64(a), EmValue::F64(b)) => EmValue::F64(a.max(*b)),
        _ => arg0.clone(),
    };

    PreHookResult::Bypass(Some(result))
}

/// Hook for `System.Math.Sign` method.
///
/// Returns -1, 0, or 1 indicating the sign of a number.
///
/// # Handled Overloads
///
/// - `Math.Sign(SByte) -> Int32`
/// - `Math.Sign(Int16) -> Int32`
/// - `Math.Sign(Int32) -> Int32`
/// - `Math.Sign(Int64) -> Int32`
/// - `Math.Sign(Single) -> Int32`
/// - `Math.Sign(Double) -> Int32`
/// - `Math.Sign(Decimal) -> Int32`
///
/// # Parameters
///
/// - `value`: A signed number
fn system_math_sign_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    let result = match arg0 {
        EmValue::I32(n) => n.signum(),
        EmValue::I64(n) => n.signum() as i32,
        EmValue::F32(f) => {
            if f.is_nan() {
                0
            } else if *f > 0.0 {
                1
            } else if *f < 0.0 {
                -1
            } else {
                0
            }
        }
        EmValue::F64(f) => {
            if f.is_nan() {
                0
            } else if *f > 0.0 {
                1
            } else if *f < 0.0 {
                -1
            } else {
                0
            }
        }
        _ => 0,
    };

    PreHookResult::Bypass(Some(EmValue::I32(result)))
}

/// Hook for `System.Math.Clamp` method.
///
/// Returns `value` clamped to the inclusive range of `min` and `max`.
///
/// # Handled Overloads
///
/// - `Math.Clamp(SByte, SByte, SByte) -> SByte`
/// - `Math.Clamp(Byte, Byte, Byte) -> Byte`
/// - `Math.Clamp(Int16, Int16, Int16) -> Int16`
/// - `Math.Clamp(UInt16, UInt16, UInt16) -> UInt16`
/// - `Math.Clamp(Int32, Int32, Int32) -> Int32`
/// - `Math.Clamp(UInt32, UInt32, UInt32) -> UInt32`
/// - `Math.Clamp(Int64, Int64, Int64) -> Int64`
/// - `Math.Clamp(UInt64, UInt64, UInt64) -> UInt64`
/// - `Math.Clamp(Single, Single, Single) -> Single`
/// - `Math.Clamp(Double, Double, Double) -> Double`
/// - `Math.Clamp(Decimal, Decimal, Decimal) -> Decimal`
///
/// # Parameters
///
/// - `value`: The value to be clamped
/// - `min`: The lower bound of the result
/// - `max`: The upper bound of the result
fn system_math_clamp_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let (Some(arg0), Some(arg1), Some(arg2)) = (ctx.args.first(), ctx.args.get(1), ctx.args.get(2))
    else {
        return PreHookResult::Bypass(ctx.args.first().cloned());
    };

    let result = match (arg0, arg1, arg2) {
        (EmValue::I32(val), EmValue::I32(min), EmValue::I32(max)) => {
            EmValue::I32(*val.max(min).min(max))
        }
        (EmValue::I64(val), EmValue::I64(min), EmValue::I64(max)) => {
            EmValue::I64(*val.max(min).min(max))
        }
        (EmValue::F32(val), EmValue::F32(min), EmValue::F32(max)) => {
            EmValue::F32(val.max(*min).min(*max))
        }
        (EmValue::F64(val), EmValue::F64(min), EmValue::F64(max)) => {
            EmValue::F64(val.max(*min).min(*max))
        }
        _ => arg0.clone(),
    };

    PreHookResult::Bypass(Some(result))
}

/// Hook for `System.Math.DivRem` method.
///
/// Calculates the quotient and remainder of two numbers.
///
/// # Handled Overloads
///
/// - `Math.DivRem(Int32, Int32, out Int32) -> Int32`
/// - `Math.DivRem(Int64, Int64, out Int64) -> Int64`
/// - `Math.DivRem(Int32, Int32) -> (Int32, Int32)` (.NET 6+)
/// - `Math.DivRem(Int64, Int64) -> (Int64, Int64)` (.NET 6+)
///
/// # Parameters
///
/// - `a`: The dividend
/// - `b`: The divisor
/// - `result` (out): The remainder (for legacy overloads)
fn system_math_divrem_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let (Some(arg0), Some(arg1)) = (ctx.args.first(), ctx.args.get(1)) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    // Use checked arithmetic: division by zero or i32::MIN/-1 overflow falls
    // back to (0, 0). The hook intentionally degrades gracefully rather than
    // raising DivideByZeroException/OverflowException, matching the existing
    // lenient style used by other Math hooks here.
    let (quotient, remainder) = match (arg0, arg1) {
        (EmValue::I32(a), EmValue::I32(b)) => match (a.checked_div(*b), a.checked_rem(*b)) {
            (Some(q), Some(r)) => (EmValue::I32(q), EmValue::I32(r)),
            _ => (EmValue::I32(0), EmValue::I32(0)),
        },
        (EmValue::I64(a), EmValue::I64(b)) => match (a.checked_div(*b), a.checked_rem(*b)) {
            (Some(q), Some(r)) => (EmValue::I64(q), EmValue::I64(r)),
            _ => (EmValue::I64(0), EmValue::I64(0)),
        },
        _ => (EmValue::I32(0), EmValue::I32(0)),
    };

    // Store remainder through the out parameter if provided
    if let Some(arg2) = ctx.args.get(2) {
        if let Some(ptr) = arg2.as_managed_ptr() {
            try_hook!(thread.store_through_pointer(ptr, remainder));
        }
    }

    PreHookResult::Bypass(Some(quotient))
}

/// Hook for `System.Math.Floor` method.
///
/// Returns the largest integral value less than or equal to the specified number.
///
/// # Handled Overloads
///
/// - `Math.Floor(Double) -> Double`
/// - `Math.Floor(Decimal) -> Decimal`
///
/// # Parameters
///
/// - `d`: A double-precision floating-point number
fn system_math_floor_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F64(0.0)));
    };

    let result = match arg0 {
        EmValue::F32(f) => EmValue::F64(f64::from(f.floor())),
        EmValue::F64(f) => EmValue::F64(f.floor()),
        _ => EmValue::F64(0.0),
    };

    PreHookResult::Bypass(Some(result))
}

/// Hook for `System.Math.Ceiling` method.
///
/// Returns the smallest integral value greater than or equal to the specified number.
///
/// # Handled Overloads
///
/// - `Math.Ceiling(Double) -> Double`
/// - `Math.Ceiling(Decimal) -> Decimal`
///
/// # Parameters
///
/// - `d`: A double-precision floating-point number
fn system_math_ceiling_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F64(0.0)));
    };

    let result = match arg0 {
        EmValue::F32(f) => EmValue::F64(f64::from(f.ceil())),
        EmValue::F64(f) => EmValue::F64(f.ceil()),
        _ => EmValue::F64(0.0),
    };

    PreHookResult::Bypass(Some(result))
}

/// Hook for `System.Math.Round` method.
///
/// `System.MidpointRounding`, by the value a call passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Midpoint {
    /// 0: a midpoint goes to the even neighbour (the default).
    ToEven,
    /// 1: a midpoint goes away from zero.
    AwayFromZero,
    /// 2: toward zero (truncation).
    ToZero,
    /// 3: toward negative infinity (floor).
    ToNegativeInfinity,
    /// 4: toward positive infinity (ceiling).
    ToPositiveInfinity,
}

impl Midpoint {
    /// The mode `value` names, or `None` for a value `MidpointRounding` has no member for.
    fn from_value(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::ToEven),
            1 => Some(Self::AwayFromZero),
            2 => Some(Self::ToZero),
            3 => Some(Self::ToNegativeInfinity),
            4 => Some(Self::ToPositiveInfinity),
            _ => None,
        }
    }
}

/// What a `Round` call asks for, read from its arguments by the overload its parameter types
/// name: `Round(x)`, `Round(x, int digits)`, `Round(x, MidpointRounding)` and
/// `Round(x, int digits, MidpointRounding)`.
///
/// `Ok(None)` declines the call: a `decimal` value (which this hook does not compute), or
/// arguments whose overload the call does not say (no parameter types and more than the
/// value, where `digits` and a mode are both an `int32` on the stack). `Err` is the throw the
/// runtime makes: digits outside `0..=max_digits` (`ArgumentOutOfRangeException`) or a mode
/// `MidpointRounding` has no member for (`ArgumentException`).
fn round_call(
    ctx: &HookContext<'_>,
    float: CilFlavor,
    max_digits: i32,
) -> std::result::Result<Option<(i32, Midpoint)>, PreHookResult> {
    let (mut digits, mut mode) = (0, Midpoint::ToEven);
    let params: Vec<CilFlavor> = match ctx.param_types {
        Some(types) => types.to_vec(),
        None if ctx.args.len() == 1 => vec![float.clone()],
        None => return Ok(None),
    };
    if params.first() != Some(&float) || params.len() != ctx.args.len() {
        return Ok(None);
    }
    for (param, arg) in params.iter().zip(ctx.args).skip(1) {
        let EmValue::I32(value) = arg else {
            return Ok(None);
        };
        match param {
            CilFlavor::I4 => {
                if !(0..=max_digits).contains(value) {
                    return Err(PreHookResult::Throw {
                        exception_type: synthetic_exception::ARGUMENT_OUT_OF_RANGE,
                        message: format!("Round: digits must be 0 to {max_digits}, got {value}"),
                    });
                }
                digits = *value;
            }
            CilFlavor::ValueType => {
                mode = Midpoint::from_value(*value).ok_or_else(|| PreHookResult::Throw {
                    exception_type: synthetic_exception::ARGUMENT_EXCEPTION,
                    message: format!("Round: {value} is no MidpointRounding"),
                })?;
            }
            _ => return Ok(None),
        }
    }
    Ok(Some((digits, mode)))
}

/// Rounds `value` to `digits` fractional digits by `mode`, as .NET's `Math.Round` does: a
/// value whose magnitude reaches `limit` (or a NaN) has no fractional digits left to round
/// and is returned as it is; otherwise it is scaled by `10^digits`, rounded to an integer
/// and scaled back.
macro_rules! round_like_dotnet {
    ($value:expr, $digits:expr, $mode:expr, $limit:expr, $float:ty) => {{
        let value: $float = $value;
        if value.is_nan() || value.abs() >= $limit {
            value
        } else {
            let power10 = (10.0 as $float).powi($digits);
            let scaled = value * power10;
            let rounded = match $mode {
                Midpoint::ToEven => scaled.round_ties_even(),
                Midpoint::AwayFromZero => {
                    let integral = scaled.trunc();
                    let fraction = scaled - integral;
                    if fraction.abs() >= 0.5 {
                        integral + fraction.signum()
                    } else {
                        integral
                    }
                }
                Midpoint::ToZero => scaled.trunc(),
                Midpoint::ToNegativeInfinity => scaled.floor(),
                Midpoint::ToPositiveInfinity => scaled.ceil(),
            };
            rounded / power10
        }
    }};
}

/// Rounds a value to the nearest integer or specified number of decimal places.
///
/// # Handled Overloads
///
/// - `Math.Round(Double) -> Double`
/// - `Math.Round(Double, Int32) -> Double`
/// - `Math.Round(Double, MidpointRounding) -> Double`
/// - `Math.Round(Double, Int32, MidpointRounding) -> Double`
///
/// A midpoint goes to the even neighbour unless a `MidpointRounding` says otherwise, and
/// `digits` is 0 to 15, as in .NET. The `Decimal` overloads are declined
/// ([`PreHookResult::Continue`]), and so is a call whose parameter types are unknown and
/// that passes more than the value, since `digits` and a mode are both an `int32` on the
/// stack.
///
/// # Parameters
///
/// - `value`: A double-precision floating-point number to be rounded
/// - `digits`: The number of fractional digits in the return value (optional)
/// - `mode`: Specification for how to round value if it is midway (optional)
fn system_math_round_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let value = match ctx.args.first() {
        Some(EmValue::F64(value)) => *value,
        Some(EmValue::F32(value)) => f64::from(*value),
        _ => return PreHookResult::Continue,
    };
    match round_call(ctx, CilFlavor::R8, 15) {
        Ok(Some((digits, mode))) => PreHookResult::Bypass(Some(EmValue::F64(round_like_dotnet!(
            value, digits, mode, 1e16, f64
        )))),
        Ok(None) => PreHookResult::Continue,
        Err(throw) => throw,
    }
}

/// Hook for `System.Math.Truncate` method.
///
/// Calculates the integral part of a number.
///
/// # Handled Overloads
///
/// - `Math.Truncate(Double) -> Double`
/// - `Math.Truncate(Decimal) -> Decimal`
///
/// # Parameters
///
/// - `d`: A number to truncate
fn system_math_truncate_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F64(0.0)));
    };

    let result = match arg0 {
        EmValue::F32(f) => EmValue::F64(f64::from(f.trunc())),
        EmValue::F64(f) => EmValue::F64(f.trunc()),
        _ => EmValue::F64(0.0),
    };

    PreHookResult::Bypass(Some(result))
}

/// Hook for `System.Math.Pow` method.
///
/// Returns a specified number raised to the specified power.
///
/// # Handled Overloads
///
/// - `Math.Pow(Double, Double) -> Double`
///
/// # Parameters
///
/// - `x`: A double-precision floating-point number to be raised to a power
/// - `y`: A double-precision floating-point number that specifies a power
fn system_math_pow_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let (Some(arg0), Some(arg1)) = (ctx.args.first(), ctx.args.get(1)) else {
        return PreHookResult::Bypass(Some(EmValue::F64(0.0)));
    };

    let base = arg0.to_f64_cil();
    let exp = arg1.to_f64_cil();

    PreHookResult::Bypass(Some(EmValue::F64(base.powf(exp))))
}

/// Hook for `System.Math.Sqrt` method.
///
/// Returns the square root of a specified number.
///
/// # Handled Overloads
///
/// - `Math.Sqrt(Double) -> Double`
///
/// # Parameters
///
/// - `d`: The number whose square root is to be found
fn system_math_sqrt_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F64(0.0)));
    };

    let value = arg0.to_f64_cil();
    PreHookResult::Bypass(Some(EmValue::F64(value.sqrt())))
}

/// Hook for `System.Math.Log` method.
///
/// Returns the natural (base e) or specified base logarithm of a number.
///
/// # Handled Overloads
///
/// - `Math.Log(Double) -> Double`
/// - `Math.Log(Double, Double) -> Double`
///
/// # Parameters
///
/// - `d`: The number whose logarithm is to be found
/// - `newBase`: The base of the logarithm (optional, defaults to e)
fn system_math_log_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F64(f64::NEG_INFINITY)));
    };

    let value = arg0.to_f64_cil();

    let result = if let Some(arg1) = ctx.args.get(1) {
        let base = arg1.to_f64_cil();
        value.log(base)
    } else {
        value.ln()
    };

    PreHookResult::Bypass(Some(EmValue::F64(result)))
}

/// Hook for `System.Math.Log10` method.
///
/// Returns the base 10 logarithm of a specified number.
///
/// # Handled Overloads
///
/// - `Math.Log10(Double) -> Double`
///
/// # Parameters
///
/// - `d`: A number whose logarithm is to be found
fn system_math_log10_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F64(f64::NEG_INFINITY)));
    };

    let value = arg0.to_f64_cil();
    PreHookResult::Bypass(Some(EmValue::F64(value.log10())))
}

/// Hook for `System.Math.Exp` method.
///
/// Returns e raised to the specified power.
///
/// # Handled Overloads
///
/// - `Math.Exp(Double) -> Double`
///
/// # Parameters
///
/// - `d`: A number specifying a power
fn system_math_exp_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F64(1.0)));
    };

    let value = arg0.to_f64_cil();
    PreHookResult::Bypass(Some(EmValue::F64(value.exp())))
}

/// Hook for `System.Math.Sin` method.
///
/// Returns the sine of the specified angle.
///
/// # Handled Overloads
///
/// - `Math.Sin(Double) -> Double`
///
/// # Parameters
///
/// - `a`: An angle, measured in radians
fn system_math_sin_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F64(0.0)));
    };

    let value = arg0.to_f64_cil();
    PreHookResult::Bypass(Some(EmValue::F64(value.sin())))
}

/// Hook for `System.Math.Cos` method.
///
/// Returns the cosine of the specified angle.
///
/// # Handled Overloads
///
/// - `Math.Cos(Double) -> Double`
///
/// # Parameters
///
/// - `d`: An angle, measured in radians
fn system_math_cos_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F64(1.0)));
    };

    let value = arg0.to_f64_cil();
    PreHookResult::Bypass(Some(EmValue::F64(value.cos())))
}

/// Hook for `System.Math.Tan` method.
///
/// Returns the tangent of the specified angle.
///
/// # Handled Overloads
///
/// - `Math.Tan(Double) -> Double`
///
/// # Parameters
///
/// - `a`: An angle, measured in radians
fn system_math_tan_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F64(0.0)));
    };

    let value = arg0.to_f64_cil();
    PreHookResult::Bypass(Some(EmValue::F64(value.tan())))
}

/// Hook for `System.Math.Asin` method.
///
/// Returns the angle whose sine is the specified number.
///
/// # Handled Overloads
///
/// - `Math.Asin(Double) -> Double`
///
/// # Parameters
///
/// - `d`: A number representing a sine, where d must be >= -1 and <= 1
fn system_math_asin_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F64(0.0)));
    };

    let value = arg0.to_f64_cil();
    PreHookResult::Bypass(Some(EmValue::F64(value.asin())))
}

/// Hook for `System.Math.Acos` method.
///
/// Returns the angle whose cosine is the specified number.
///
/// # Handled Overloads
///
/// - `Math.Acos(Double) -> Double`
///
/// # Parameters
///
/// - `d`: A number representing a cosine, where d must be >= -1 and <= 1
fn system_math_acos_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F64(std::f64::consts::FRAC_PI_2)));
    };

    let value = arg0.to_f64_cil();
    PreHookResult::Bypass(Some(EmValue::F64(value.acos())))
}

/// Hook for `System.Math.Atan` method.
///
/// Returns the angle whose tangent is the specified number.
///
/// # Handled Overloads
///
/// - `Math.Atan(Double) -> Double`
///
/// # Parameters
///
/// - `d`: A number representing a tangent
fn system_math_atan_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F64(0.0)));
    };

    let value = arg0.to_f64_cil();
    PreHookResult::Bypass(Some(EmValue::F64(value.atan())))
}

/// Hook for `System.Math.Atan2` method.
///
/// Returns the angle whose tangent is the quotient of two specified numbers.
///
/// # Handled Overloads
///
/// - `Math.Atan2(Double, Double) -> Double`
///
/// # Parameters
///
/// - `y`: The y coordinate of a point
/// - `x`: The x coordinate of a point
fn system_math_atan2_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let (Some(arg0), Some(arg1)) = (ctx.args.first(), ctx.args.get(1)) else {
        return PreHookResult::Bypass(Some(EmValue::F64(0.0)));
    };

    let y = arg0.to_f64_cil();
    let x = arg1.to_f64_cil();

    PreHookResult::Bypass(Some(EmValue::F64(y.atan2(x))))
}

/// Hook for `System.Numerics.BitOperations.PopCount` method.
///
/// Returns the population count (number of bits set) of an integer.
///
/// # Handled Overloads
///
/// - `BitOperations.PopCount(UInt32) -> Int32`
/// - `BitOperations.PopCount(UInt64) -> Int32`
/// - `BitOperations.PopCount(UIntPtr) -> Int32`
///
/// # Parameters
///
/// - `value`: The value whose set bits are to be counted
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]
fn system_numerics_bitoperations_popcount_pre(
    ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    let count = match arg0 {
        EmValue::I32(n) => (*n as u32).count_ones() as i32,
        EmValue::I64(n) => (*n as u64).count_ones() as i32,
        _ => 0,
    };

    PreHookResult::Bypass(Some(EmValue::I32(count)))
}

/// Hook for `System.Numerics.BitOperations.LeadingZeroCount` method.
///
/// Counts the number of leading zero bits in an integer.
///
/// # Handled Overloads
///
/// - `BitOperations.LeadingZeroCount(UInt32) -> Int32`
/// - `BitOperations.LeadingZeroCount(UInt64) -> Int32`
/// - `BitOperations.LeadingZeroCount(UIntPtr) -> Int32`
///
/// # Parameters
///
/// - `value`: The value whose leading zeros are to be counted
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]
fn system_numerics_bitoperations_leadingzerocount_pre(
    ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::I32(32)));
    };

    let count = match arg0 {
        EmValue::I32(n) => (*n as u32).leading_zeros() as i32,
        EmValue::I64(n) => (*n as u64).leading_zeros() as i32,
        _ => 32,
    };

    PreHookResult::Bypass(Some(EmValue::I32(count)))
}

/// Hook for `System.Numerics.BitOperations.TrailingZeroCount` method.
///
/// Counts the number of trailing zero bits in an integer.
///
/// # Handled Overloads
///
/// - `BitOperations.TrailingZeroCount(Int32) -> Int32`
/// - `BitOperations.TrailingZeroCount(Int64) -> Int32`
/// - `BitOperations.TrailingZeroCount(UInt32) -> Int32`
/// - `BitOperations.TrailingZeroCount(UInt64) -> Int32`
/// - `BitOperations.TrailingZeroCount(IntPtr) -> Int32`
/// - `BitOperations.TrailingZeroCount(UIntPtr) -> Int32`
///
/// # Parameters
///
/// - `value`: The value whose trailing zeros are to be counted
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]
fn system_numerics_bitoperations_trailingzerocount_pre(
    ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::I32(32)));
    };

    let count = match arg0 {
        EmValue::I32(n) => (*n as u32).trailing_zeros() as i32,
        EmValue::I64(n) => (*n as u64).trailing_zeros() as i32,
        _ => 32,
    };

    PreHookResult::Bypass(Some(EmValue::I32(count)))
}

/// Hook for `System.Numerics.BitOperations.RotateLeft` method.
///
/// Rotates the specified value left by the specified number of bits.
///
/// # Handled Overloads
///
/// - `BitOperations.RotateLeft(UInt32, Int32) -> UInt32`
/// - `BitOperations.RotateLeft(UInt64, Int32) -> UInt64`
/// - `BitOperations.RotateLeft(UIntPtr, Int32) -> UIntPtr`
///
/// # Parameters
///
/// - `value`: The value to rotate
/// - `offset`: The number of bits to rotate by
#[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
fn system_numerics_bitoperations_rotateleft_pre(
    ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    let (Some(arg0), Some(arg1)) = (ctx.args.first(), ctx.args.get(1)) else {
        return PreHookResult::Bypass(ctx.args.first().cloned());
    };

    let shift = match arg1 {
        EmValue::I32(n) => *n as u32,
        _ => return PreHookResult::Bypass(Some(arg0.clone())),
    };

    let result = match arg0 {
        EmValue::I32(n) => EmValue::I32((*n as u32).rotate_left(shift) as i32),
        EmValue::I64(n) => EmValue::I64((*n as u64).rotate_left(shift) as i64),
        _ => arg0.clone(),
    };

    PreHookResult::Bypass(Some(result))
}

/// Hook for `System.Numerics.BitOperations.RotateRight` method.
///
/// Rotates the specified value right by the specified number of bits.
///
/// # Handled Overloads
///
/// - `BitOperations.RotateRight(UInt32, Int32) -> UInt32`
/// - `BitOperations.RotateRight(UInt64, Int32) -> UInt64`
/// - `BitOperations.RotateRight(UIntPtr, Int32) -> UIntPtr`
///
/// # Parameters
///
/// - `value`: The value to rotate
/// - `offset`: The number of bits to rotate by
#[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
fn system_numerics_bitoperations_rotateright_pre(
    ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    let (Some(arg0), Some(arg1)) = (ctx.args.first(), ctx.args.get(1)) else {
        return PreHookResult::Bypass(ctx.args.first().cloned());
    };

    let shift = match arg1 {
        EmValue::I32(n) => *n as u32,
        _ => return PreHookResult::Bypass(Some(arg0.clone())),
    };

    let result = match arg0 {
        EmValue::I32(n) => EmValue::I32((*n as u32).rotate_right(shift) as i32),
        EmValue::I64(n) => EmValue::I64((*n as u64).rotate_right(shift) as i64),
        _ => arg0.clone(),
    };

    PreHookResult::Bypass(Some(result))
}

/// Hook for `System.Math.Log2` method.
///
/// Returns the base-2 logarithm of a specified number.
///
/// # Handled Overloads
///
/// - `Math.Log2(Double) -> Double`
///
/// # Parameters
///
/// - `x`: The number whose base-2 logarithm is to be found
fn system_math_log2_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F64(f64::NEG_INFINITY)));
    };

    let value = arg0.to_f64_cil();
    PreHookResult::Bypass(Some(EmValue::F64(value.log2())))
}

/// Hook for `System.MathF.Abs` — absolute value (single-precision).
fn system_mathf_abs_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F32(0.0)));
    };
    PreHookResult::Bypass(Some(EmValue::F32(arg0.to_f32_cil().abs())))
}

/// Hook for `System.MathF.Sin` — sine (single-precision).
fn system_mathf_sin_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F32(0.0)));
    };
    PreHookResult::Bypass(Some(EmValue::F32(arg0.to_f32_cil().sin())))
}

/// Hook for `System.MathF.Cos` — cosine (single-precision).
fn system_mathf_cos_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F32(1.0)));
    };
    PreHookResult::Bypass(Some(EmValue::F32(arg0.to_f32_cil().cos())))
}

/// Hook for `System.MathF.Sqrt` — square root (single-precision).
fn system_mathf_sqrt_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F32(0.0)));
    };
    PreHookResult::Bypass(Some(EmValue::F32(arg0.to_f32_cil().sqrt())))
}

/// Hook for `System.MathF.Floor` — round down (single-precision).
fn system_mathf_floor_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F32(0.0)));
    };
    PreHookResult::Bypass(Some(EmValue::F32(arg0.to_f32_cil().floor())))
}

/// Hook for `System.MathF.Ceiling` — round up (single-precision).
fn system_mathf_ceiling_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F32(0.0)));
    };
    PreHookResult::Bypass(Some(EmValue::F32(arg0.to_f32_cil().ceil())))
}

/// Hook for `System.MathF.Round`: `Round(Single)`, `Round(Single, Int32)`,
/// `Round(Single, MidpointRounding)` and `Round(Single, Int32, MidpointRounding)`, rounded as
/// .NET's `MathF.Round` does in single precision (a midpoint to the even neighbour by default,
/// `digits` 0 to 6, a magnitude of 1e8 or more returned as it is).
fn system_mathf_round_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::F32(value)) = ctx.args.first() else {
        return PreHookResult::Continue;
    };
    let value = *value;
    match round_call(ctx, CilFlavor::R4, 6) {
        Ok(Some((digits, mode))) => PreHookResult::Bypass(Some(EmValue::F32(round_like_dotnet!(
            value, digits, mode, 1e8, f32
        )))),
        Ok(None) => PreHookResult::Continue,
        Err(throw) => throw,
    }
}

/// Hook for `System.MathF.Min` — minimum of two values (single-precision).
fn system_mathf_min_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let (Some(arg0), Some(arg1)) = (ctx.args.first(), ctx.args.get(1)) else {
        return PreHookResult::Bypass(ctx.args.first().cloned());
    };
    let a = arg0.to_f32_cil();
    let b = arg1.to_f32_cil();
    PreHookResult::Bypass(Some(EmValue::F32(a.min(b))))
}

/// Hook for `System.MathF.Max` — maximum of two values (single-precision).
fn system_mathf_max_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let (Some(arg0), Some(arg1)) = (ctx.args.first(), ctx.args.get(1)) else {
        return PreHookResult::Bypass(ctx.args.first().cloned());
    };
    let a = arg0.to_f32_cil();
    let b = arg1.to_f32_cil();
    PreHookResult::Bypass(Some(EmValue::F32(a.max(b))))
}

/// Hook for `System.MathF.Pow` — power (single-precision).
fn system_mathf_pow_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let (Some(arg0), Some(arg1)) = (ctx.args.first(), ctx.args.get(1)) else {
        return PreHookResult::Bypass(Some(EmValue::F32(0.0)));
    };
    let base = arg0.to_f32_cil();
    let exp = arg1.to_f32_cil();
    PreHookResult::Bypass(Some(EmValue::F32(base.powf(exp))))
}

/// Hook for `System.MathF.Log` — natural or custom base logarithm (single-precision).
fn system_mathf_log_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F32(f32::NEG_INFINITY)));
    };
    let value = arg0.to_f32_cil();
    let result = if let Some(arg1) = ctx.args.get(1) {
        let base = arg1.to_f32_cil();
        value.log(base)
    } else {
        value.ln()
    };
    PreHookResult::Bypass(Some(EmValue::F32(result)))
}

/// Hook for `System.MathF.Log2` — base-2 logarithm (single-precision).
fn system_mathf_log2_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F32(f32::NEG_INFINITY)));
    };
    PreHookResult::Bypass(Some(EmValue::F32(arg0.to_f32_cil().log2())))
}

/// Hook for `System.MathF.Log10` — base-10 logarithm (single-precision).
fn system_mathf_log10_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F32(f32::NEG_INFINITY)));
    };
    PreHookResult::Bypass(Some(EmValue::F32(arg0.to_f32_cil().log10())))
}

/// Hook for `System.MathF.Tan` — tangent (single-precision).
fn system_mathf_tan_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F32(0.0)));
    };
    PreHookResult::Bypass(Some(EmValue::F32(arg0.to_f32_cil().tan())))
}

/// Hook for `System.MathF.Asin` — inverse sine (single-precision).
fn system_mathf_asin_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F32(0.0)));
    };
    PreHookResult::Bypass(Some(EmValue::F32(arg0.to_f32_cil().asin())))
}

/// Hook for `System.MathF.Acos` — inverse cosine (single-precision).
fn system_mathf_acos_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F32(std::f32::consts::FRAC_PI_2)));
    };
    PreHookResult::Bypass(Some(EmValue::F32(arg0.to_f32_cil().acos())))
}

/// Hook for `System.MathF.Atan` — inverse tangent (single-precision).
fn system_mathf_atan_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F32(0.0)));
    };
    PreHookResult::Bypass(Some(EmValue::F32(arg0.to_f32_cil().atan())))
}

/// Hook for `System.MathF.Atan2` — two-argument arctangent (single-precision).
fn system_mathf_atan2_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let (Some(arg0), Some(arg1)) = (ctx.args.first(), ctx.args.get(1)) else {
        return PreHookResult::Bypass(Some(EmValue::F32(0.0)));
    };
    let y = arg0.to_f32_cil();
    let x = arg1.to_f32_cil();
    PreHookResult::Bypass(Some(EmValue::F32(y.atan2(x))))
}

/// Hook for `System.MathF.Exp` — e raised to a power (single-precision).
fn system_mathf_exp_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F32(1.0)));
    };
    PreHookResult::Bypass(Some(EmValue::F32(arg0.to_f32_cil().exp())))
}

/// Hook for `System.MathF.Truncate` — remove fractional part (single-precision).
fn system_mathf_truncate_pre(
    ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::F32(0.0)));
    };
    PreHookResult::Bypass(Some(EmValue::F32(arg0.to_f32_cil().trunc())))
}

/// Hook for `System.MathF.Sign` — returns -1, 0, or 1 (single-precision input).
#[allow(clippy::cast_possible_truncation)]
fn system_mathf_sign_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };
    let f = arg0.to_f32_cil();
    let result = if f.is_nan() {
        0
    } else if f > 0.0 {
        1
    } else if f < 0.0 {
        -1
    } else {
        0
    };
    PreHookResult::Bypass(Some(EmValue::I32(result)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        emulation::runtime::HookManager,
        metadata::{token::Token, typesystem::PointerSize},
        testkit::emulation::create_test_thread,
    };

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        register(&manager).unwrap();

        // Should have registered all math hooks (Math + MathF + BitOperations)
        assert_eq!(manager.len(), 49);
    }

    #[test]
    fn test_abs_hook() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::I32(-5)]);

        let result = system_math_abs_pre(&ctx, &mut thread);
        match result {
            PreHookResult::Bypass(Some(EmValue::I32(5))) => {}
            _ => panic!("Expected Bypass(Some(I32(5)))"),
        }
    }

    #[test]
    fn test_min_hook() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::I32(3), EmValue::I32(7)]);

        let result = system_math_min_pre(&ctx, &mut thread);
        match result {
            PreHookResult::Bypass(Some(EmValue::I32(3))) => {}
            _ => panic!("Expected Bypass(Some(I32(3)))"),
        }
    }

    #[test]
    fn test_max_hook() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::I32(3), EmValue::I32(7)]);

        let result = system_math_max_pre(&ctx, &mut thread);
        match result {
            PreHookResult::Bypass(Some(EmValue::I32(7))) => {}
            _ => panic!("Expected Bypass(Some(I32(7)))"),
        }
    }

    #[test]
    fn test_pow_hook() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::F64(2.0), EmValue::F64(3.0)]);

        let result = system_math_pow_pre(&ctx, &mut thread);
        match result {
            PreHookResult::Bypass(Some(EmValue::F64(val))) if (val - 8.0).abs() < 0.001 => {}
            _ => panic!("Expected Bypass(Some(F64(8.0)))"),
        }
    }

    #[test]
    fn test_rotate_left_hook() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::I32(1), EmValue::I32(4)]);

        let result = system_numerics_bitoperations_rotateleft_pre(&ctx, &mut thread);
        match result {
            PreHookResult::Bypass(Some(EmValue::I32(16))) => {}
            _ => panic!("Expected Bypass(Some(I32(16)))"),
        }
    }

    fn create_test_context(args: &[EmValue]) -> HookContext<'_> {
        HookContext::new(
            Token::new(0x06000001),
            "System",
            "Math",
            "Abs",
            PointerSize::Bit64,
        )
        .with_args(args)
    }

    #[test]
    fn test_abs_f64() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::F64(-3.125)]);
        let result = system_math_abs_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::F64(v))) = result {
            assert!((v - 3.125).abs() < 0.001);
        } else {
            panic!("Expected Bypass with F64");
        }
    }

    #[test]
    fn test_abs_i64() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::I64(-100)]);
        let result = system_math_abs_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I64(100)))
        ));
    }

    #[test]
    fn test_sign_positive() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::I32(42)]);
        let result = system_math_sign_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));
    }

    #[test]
    fn test_sign_negative() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::I32(-42)]);
        let result = system_math_sign_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(-1)))
        ));
    }

    #[test]
    fn test_sign_zero() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::I32(0)]);
        let result = system_math_sign_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0)))
        ));
    }

    #[test]
    fn test_clamp() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::I32(15), EmValue::I32(0), EmValue::I32(10)]);
        let result = system_math_clamp_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(10)))
        ));
    }

    #[test]
    fn test_floor() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::F64(3.7)]);
        let result = system_math_floor_pre(&ctx, &mut thread);
        assert!(
            matches!(result, PreHookResult::Bypass(Some(EmValue::F64(v))) if (v - 3.0).abs() < 0.001)
        );
    }

    #[test]
    fn test_ceiling() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::F64(3.2)]);
        let result = system_math_ceiling_pre(&ctx, &mut thread);
        assert!(
            matches!(result, PreHookResult::Bypass(Some(EmValue::F64(v))) if (v - 4.0).abs() < 0.001)
        );
    }

    #[test]
    fn test_round() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::F64(3.5)]);
        let result = system_math_round_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::F64(v))) = result {
            // Banker's rounding: 3.5 rounds to 4.0
            assert!((v - 4.0).abs() < 0.001);
        } else {
            panic!("Expected Bypass with F64");
        }
    }

    #[test]
    fn test_truncate() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::F64(3.9)]);
        let result = system_math_truncate_pre(&ctx, &mut thread);
        assert!(
            matches!(result, PreHookResult::Bypass(Some(EmValue::F64(v))) if (v - 3.0).abs() < 0.001)
        );
    }

    #[test]
    fn test_sqrt() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::F64(16.0)]);
        let result = system_math_sqrt_pre(&ctx, &mut thread);
        assert!(
            matches!(result, PreHookResult::Bypass(Some(EmValue::F64(v))) if (v - 4.0).abs() < 0.001)
        );
    }

    #[test]
    fn test_log_natural() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::F64(std::f64::consts::E)]);
        let result = system_math_log_pre(&ctx, &mut thread);
        assert!(
            matches!(result, PreHookResult::Bypass(Some(EmValue::F64(v))) if (v - 1.0).abs() < 0.001)
        );
    }

    #[test]
    fn test_log10() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::F64(100.0)]);
        let result = system_math_log10_pre(&ctx, &mut thread);
        assert!(
            matches!(result, PreHookResult::Bypass(Some(EmValue::F64(v))) if (v - 2.0).abs() < 0.001)
        );
    }

    #[test]
    fn test_exp() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::F64(1.0)]);
        let result = system_math_exp_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::F64(v))) = result {
            assert!((v - std::f64::consts::E).abs() < 0.001);
        } else {
            panic!("Expected Bypass with F64");
        }
    }

    #[test]
    fn test_sin() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::F64(0.0)]);
        let result = system_math_sin_pre(&ctx, &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(Some(EmValue::F64(v))) if v.abs() < 0.001));
    }

    #[test]
    fn test_cos() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::F64(0.0)]);
        let result = system_math_cos_pre(&ctx, &mut thread);
        assert!(
            matches!(result, PreHookResult::Bypass(Some(EmValue::F64(v))) if (v - 1.0).abs() < 0.001)
        );
    }

    #[test]
    fn test_tan() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::F64(0.0)]);
        let result = system_math_tan_pre(&ctx, &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(Some(EmValue::F64(v))) if v.abs() < 0.001));
    }

    #[test]
    fn test_atan2() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::F64(1.0), EmValue::F64(1.0)]);
        let result = system_math_atan2_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::F64(v))) = result {
            assert!((v - std::f64::consts::FRAC_PI_4).abs() < 0.001);
        } else {
            panic!("Expected Bypass with F64");
        }
    }

    #[test]
    fn test_popcount() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::I32(0b1010_1010)]);
        let result = system_numerics_bitoperations_popcount_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(4)))
        ));
    }

    #[test]
    fn test_leading_zero_count() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::I32(1)]);
        let result = system_numerics_bitoperations_leadingzerocount_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(31)))
        ));
    }

    #[test]
    fn test_rotate_right() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::I32(16), EmValue::I32(4)]);
        let result = system_numerics_bitoperations_rotateright_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));
    }

    #[test]
    fn test_min_with_f64() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::F64(3.125), EmValue::F64(2.75)]);
        let result = system_math_min_pre(&ctx, &mut thread);
        assert!(
            matches!(result, PreHookResult::Bypass(Some(EmValue::F64(v))) if (v - 2.75).abs() < 0.001)
        );
    }

    #[test]
    fn test_max_with_f64() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::F64(3.125), EmValue::F64(2.75)]);
        let result = system_math_max_pre(&ctx, &mut thread);
        assert!(
            matches!(result, PreHookResult::Bypass(Some(EmValue::F64(v))) if (v - 3.125).abs() < 0.001)
        );
    }

    /// `Round` follows .NET by the overload its parameter types name: a midpoint goes to the
    /// even neighbour unless a `MidpointRounding` says otherwise, `digits` is 0 to 15 (6 for
    /// `MathF`), what the runtime refuses is thrown, a NaN or a value past the rounding limit
    /// comes back as it is, and a `decimal` or an overload the call does not name is
    /// declined. Every expected value is exactly representable, so the cases test the rule,
    /// not the scaling.
    #[test]
    fn round_follows_dotnet_by_overload() {
        let mut thread = create_test_thread();
        let (r8, i4, mode) = (CilFlavor::R8, CilFlavor::I4, CilFlavor::ValueType);
        let cases: Vec<(Vec<EmValue>, Vec<CilFlavor>, Option<f64>)> = vec![
            (vec![EmValue::F64(2.5)], vec![r8.clone()], Some(2.0)),
            (vec![EmValue::F64(3.5)], vec![r8.clone()], Some(4.0)),
            (vec![EmValue::F64(-2.5)], vec![r8.clone()], Some(-2.0)),
            (vec![EmValue::F64(2.4)], vec![r8.clone()], Some(2.0)),
            (
                vec![EmValue::F64(2.5), EmValue::I32(1)],
                vec![r8.clone(), mode.clone()],
                Some(3.0),
            ),
            (
                vec![EmValue::F64(-2.5), EmValue::I32(1)],
                vec![r8.clone(), mode.clone()],
                Some(-3.0),
            ),
            (
                vec![EmValue::F64(-2.5), EmValue::I32(2)],
                vec![r8.clone(), mode.clone()],
                Some(-2.0),
            ),
            (
                vec![EmValue::F64(-2.25), EmValue::I32(3)],
                vec![r8.clone(), mode.clone()],
                Some(-3.0),
            ),
            (
                vec![EmValue::F64(2.25), EmValue::I32(4)],
                vec![r8.clone(), mode.clone()],
                Some(3.0),
            ),
            (
                vec![EmValue::F64(1.125), EmValue::I32(2)],
                vec![r8.clone(), i4.clone()],
                Some(1.12),
            ),
            (
                vec![EmValue::F64(1.125), EmValue::I32(2), EmValue::I32(1)],
                vec![r8.clone(), i4.clone(), mode.clone()],
                Some(1.13),
            ),
            (vec![EmValue::F64(1e17 + 0.0)], vec![r8.clone()], Some(1e17)),
        ];
        for (args, params, expected) in cases {
            let ctx = create_test_context(&args).with_param_types(Some(&params));
            match (system_math_round_pre(&ctx, &mut thread), expected) {
                (PreHookResult::Bypass(Some(EmValue::F64(got))), Some(want)) => {
                    assert_eq!(got, want, "{args:?}");
                }
                (other, _) => panic!("{args:?}: {other:?}"),
            }
        }

        let nan = create_test_context(&[EmValue::F64(f64::NAN)]);
        assert!(matches!(
            system_math_round_pre(&nan, &mut thread),
            PreHookResult::Bypass(Some(EmValue::F64(v))) if v.is_nan()
        ));

        let mut throws = |args: &[EmValue], params: &[CilFlavor]| {
            let ctx = create_test_context(args).with_param_types(Some(params));
            matches!(
                system_math_round_pre(&ctx, &mut thread),
                PreHookResult::Throw { .. }
            )
        };
        assert!(throws(
            &[EmValue::F64(1.0), EmValue::I32(16)],
            &[r8.clone(), i4.clone()]
        ));
        assert!(throws(
            &[EmValue::F64(1.0), EmValue::I32(-1)],
            &[r8.clone(), i4.clone()]
        ));
        assert!(throws(
            &[EmValue::F64(1.0), EmValue::I32(5)],
            &[r8.clone(), mode.clone()]
        ));

        // `digits` and a mode are both an int32: without parameter types it is declined.
        let unknown = create_test_context(&[EmValue::F64(2.5), EmValue::I32(1)]);
        assert!(matches!(
            system_math_round_pre(&unknown, &mut thread),
            PreHookResult::Continue
        ));
        let decimal_params = [mode.clone()];
        let decimal =
            create_test_context(&[EmValue::F64(2.5)]).with_param_types(Some(&decimal_params));
        assert!(matches!(
            system_math_round_pre(&decimal, &mut thread),
            PreHookResult::Continue
        ));

        // MathF: single precision, digits 0 to 6.
        let single = create_test_context(&[EmValue::F32(2.5)]);
        assert!(matches!(
            system_mathf_round_pre(&single, &mut thread),
            PreHookResult::Bypass(Some(EmValue::F32(v))) if v == 2.0
        ));
        let r4 = [CilFlavor::R4, i4];
        let seven =
            create_test_context(&[EmValue::F32(1.0), EmValue::I32(7)]).with_param_types(Some(&r4));
        assert!(matches!(
            system_mathf_round_pre(&seven, &mut thread),
            PreHookResult::Throw { .. }
        ));
    }
}

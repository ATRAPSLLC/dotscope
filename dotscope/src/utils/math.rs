//! Mathematical utility functions.

use crate::{ParseFailure, ParseStage, Result};

/// Converts a `usize` to `u32` for PE serialization, returning an error if the value
/// exceeds `u32::MAX`. All .NET metadata structures are bounded well below this limit.
///
/// # Errors
///
/// Returns an error if `value` exceeds `u32::MAX`.
pub fn to_u32(value: usize) -> Result<u32> {
    u32::try_from(value).map_err(|_| {
        ParseFailure::InvalidField {
            stage: ParseStage::Generic,
            field: "u32_value",
            reason: format!("PE serialization value {value} exceeds u32::MAX"),
        }
        .into()
    })
}

/// Converts a `usize` to `i32` with saturation at `i32::MAX`.
///
/// Useful for returning array lengths and similar values to .NET code,
/// where `int` is the expected return type.
#[must_use]
#[cfg(feature = "emulation")]
pub fn to_i32_saturating(value: usize) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

/// Checks if a value is a power of two and returns the exponent.
///
/// Returns `Some(n)` if `value == 2^n`, `None` otherwise.
/// Only works for positive values.
///
/// # Examples
///
/// The `examples::is_power_of_two_example` test in this module runs this example.
#[must_use]
#[allow(clippy::cast_sign_loss)] // value > 0 verified above
#[allow(clippy::cast_possible_truncation)] // trailing_zeros <= 63 for u64
pub fn is_power_of_two(value: i64) -> Option<u8> {
    if value <= 0 {
        return None;
    }
    let value = value as u64;
    if value.is_power_of_two() {
        Some(value.trailing_zeros() as u8)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_power_of_two() {
        assert_eq!(is_power_of_two(1), Some(0));
        assert_eq!(is_power_of_two(2), Some(1));
        assert_eq!(is_power_of_two(4), Some(2));
        assert_eq!(is_power_of_two(8), Some(3));
        assert_eq!(is_power_of_two(16), Some(4));
        assert_eq!(is_power_of_two(32), Some(5));
        assert_eq!(is_power_of_two(64), Some(6));
        assert_eq!(is_power_of_two(128), Some(7));
        assert_eq!(is_power_of_two(256), Some(8));
        assert_eq!(is_power_of_two(1024), Some(10));
        assert_eq!(is_power_of_two(1 << 20), Some(20));
        assert_eq!(is_power_of_two(1 << 30), Some(30));
    }

    #[test]
    fn test_to_u32_valid() {
        assert_eq!(to_u32(0).unwrap(), 0);
        assert_eq!(to_u32(1).unwrap(), 1);
        assert_eq!(to_u32(u32::MAX as usize).unwrap(), u32::MAX);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn test_to_u32_overflow() {
        assert!(to_u32(u32::MAX as usize + 1).is_err());
        assert!(to_u32(usize::MAX).is_err());
    }

    #[cfg(feature = "emulation")]
    #[test]
    fn test_to_i32_saturating_in_range() {
        assert_eq!(to_i32_saturating(0), 0);
        assert_eq!(to_i32_saturating(1), 1);
        assert_eq!(to_i32_saturating(i32::MAX as usize), i32::MAX);
    }

    #[cfg(feature = "emulation")]
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn test_to_i32_saturating_overflow() {
        assert_eq!(to_i32_saturating(i32::MAX as usize + 1), i32::MAX);
        assert_eq!(to_i32_saturating(usize::MAX), i32::MAX);
    }

    #[test]
    fn test_is_power_of_two_non_powers() {
        assert_eq!(is_power_of_two(0), None);
        assert_eq!(is_power_of_two(-1), None);
        assert_eq!(is_power_of_two(-8), None);
        assert_eq!(is_power_of_two(3), None);
        assert_eq!(is_power_of_two(5), None);
        assert_eq!(is_power_of_two(6), None);
        assert_eq!(is_power_of_two(7), None);
        assert_eq!(is_power_of_two(9), None);
        assert_eq!(is_power_of_two(15), None);
        assert_eq!(is_power_of_two(17), None);
    }
}

#[cfg(test)]
mod examples {
    use super::*;
    use crate::Result;

    #[test]
    fn is_power_of_two_example() -> Result<()> {
        assert_eq!(is_power_of_two(1), Some(0)); // 2^0 = 1
        assert_eq!(is_power_of_two(2), Some(1)); // 2^1 = 2
        assert_eq!(is_power_of_two(8), Some(3)); // 2^3 = 8
        assert_eq!(is_power_of_two(0), None);
        assert_eq!(is_power_of_two(-8), None);
        assert_eq!(is_power_of_two(6), None);
        Ok(())
    }
}

//! Memory alignment utilities for binary layouts and ECMA-335 compliance.
//!
//! This module provides efficient alignment functions required for proper .NET metadata
//! formatting and PE binary layout. All functions use optimized bitwise operations for
//! high-performance alignment calculations.
//!
//! # ECMA-335 Alignment Requirements
//!
//! The ECMA-335 specification requires specific alignment for metadata structures:
//! - **Metadata Heaps**: 4-byte alignment (#Strings, #Blob, #GUID, #US)
//! - **Table Entries**: Natural alignment based on field sizes
//! - **Stream Data**: 4-byte alignment for optimal access
//!
//! # PE Format Alignment
//!
//! PE executable format requires various alignments:
//! - **File Alignment**: Typically 512 bytes for disk efficiency
//! - **Section Alignment**: Typically 4096 bytes for memory pages
//! - **Data Alignment**: 16 bytes for SIMD optimization
//!
//! # Examples
//!
//! The `examples::module_example` test in this module runs this example.

/// Aligns a value to the next 4-byte boundary as required by ECMA-335 metadata heaps.
///
/// This function performs the standard 4-byte alignment required throughout .NET metadata
/// structures. The ECMA-335 specification requires 4-byte alignment for optimal access
/// performance and compliance with the Common Language Runtime.
///
/// # Arguments
///
/// * `value` - The byte offset or size value to align
///
/// # Returns
///
/// Returns the input value rounded up to the next 4-byte boundary. If the input is
/// already 4-byte aligned, it is returned unchanged.
///
/// # Examples
///
/// The `examples::align_to_4_bytes_example` test in this module runs this example.
#[inline]
pub fn align_to_4_bytes(value: u64) -> u64 {
    value.saturating_add(3) & !3
}

/// Aligns a value to an arbitrary power-of-2 boundary for PE sections and memory layout.
///
/// This function provides flexible alignment for various binary format requirements,
/// particularly PE section alignment, memory page alignment, and structured binary
/// layouts that require power-of-2 boundaries.
///
/// # Arguments
///
/// * `value` - The byte offset or size value to align
/// * `alignment` - The alignment boundary, which **must be a power of 2**
///
/// # Returns
///
/// Returns the input value rounded up to the next alignment boundary. If the input is
/// already aligned to the specified boundary, it is returned unchanged.
///
/// # Power-of-2 Requirement
///
/// The alignment parameter must be a power of 2 for the bitwise alignment algorithm
/// to work correctly. Valid alignments include: 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 4096, etc.
///
/// # Examples
///
/// The `examples::align_to_example` test in this module runs this example.
#[inline]
pub fn align_to(value: u64, alignment: u64) -> u64 {
    debug_assert!(
        alignment.is_power_of_two(),
        "alignment must be a power of 2, got {alignment}"
    );
    let mask = alignment.saturating_sub(1);
    value.saturating_add(mask) & !mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align_to_4_bytes() {
        assert_eq!(align_to_4_bytes(0), 0);
        assert_eq!(align_to_4_bytes(1), 4);
        assert_eq!(align_to_4_bytes(2), 4);
        assert_eq!(align_to_4_bytes(3), 4);
        assert_eq!(align_to_4_bytes(4), 4);
        assert_eq!(align_to_4_bytes(5), 8);
        assert_eq!(align_to_4_bytes(8), 8);
        assert_eq!(align_to_4_bytes(9), 12);
    }

    #[test]
    fn test_align_to() {
        // Test various power-of-2 alignments
        assert_eq!(align_to(100, 16), 112);
        assert_eq!(align_to(112, 16), 112);
        assert_eq!(align_to(113, 16), 128);
        assert_eq!(align_to(128, 16), 128);

        assert_eq!(align_to(200, 256), 256);
        assert_eq!(align_to(256, 256), 256);
        assert_eq!(align_to(300, 256), 512);

        assert_eq!(align_to(1000, 512), 1024);
        assert_eq!(align_to(1024, 512), 1024);
        assert_eq!(align_to(1500, 512), 1536);
    }

    #[test]
    fn test_alignment_properties() {
        let test_alignments = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];

        for &alignment in &test_alignments {
            for test_value in [1, alignment - 1, alignment, alignment + 1, alignment * 2] {
                let aligned = align_to(test_value, alignment);

                // Result should be >= input
                assert!(aligned >= test_value);

                // Result should be properly aligned
                assert_eq!(
                    aligned % alignment,
                    0,
                    "align_to({test_value}, {alignment}) = {aligned} is not aligned"
                );

                // Should not over-align
                assert!(
                    aligned < test_value + alignment,
                    "align_to({test_value}, {alignment}) = {aligned} over-aligned"
                );
            }
        }
    }

    #[test]
    fn test_4_byte_alignment_properties() {
        for test_value in 0..20u64 {
            let aligned = align_to_4_bytes(test_value);

            // Alignment is always >= original value
            assert!(aligned >= test_value);

            // Result is always 4-byte aligned (except for 0)
            if aligned != 0 {
                assert_eq!(
                    aligned % 4,
                    0,
                    "Value {test_value} aligned to {aligned} is not 4-byte aligned"
                );
            }

            // Alignment never adds more than 3 bytes
            assert!(aligned - test_value < 4, "Alignment added too many bytes");
        }
    }

    #[test]
    #[should_panic(expected = "alignment must be a power of 2")]
    #[cfg(debug_assertions)]
    fn test_align_to_non_power_of_2_panics() {
        // This should panic in debug builds because 3 is not a power of 2
        let _ = align_to(100, 3);
    }

    #[test]
    #[cfg(debug_assertions)]
    fn test_align_to_zero_alignment_panics() {
        // Zero is not a power of 2, should panic
        let result = std::panic::catch_unwind(|| align_to(100, 0));
        assert!(result.is_err(), "align_to with 0 alignment should panic");
    }
}

#[cfg(test)]
mod examples {
    use super::*;
    use crate::Result;

    #[test]
    fn module_example() -> Result<()> {
        // ECMA-335 metadata heap alignment
        assert_eq!(align_to_4_bytes(17), 20);
        assert_eq!(align_to_4_bytes(20), 20); // Already aligned

        // PE section alignment
        assert_eq!(align_to(1000, 512), 1024); // File alignment
        assert_eq!(align_to(5000, 4096), 8192); // Memory alignment
        Ok(())
    }

    #[test]
    fn align_to_4_bytes_example() -> Result<()> {
        assert_eq!(align_to_4_bytes(1), 4);
        assert_eq!(align_to_4_bytes(4), 4); // Already aligned
        assert_eq!(align_to_4_bytes(17), 20);
        assert_eq!(align_to_4_bytes(100), 100); // Already aligned
        Ok(())
    }

    #[test]
    fn align_to_example() -> Result<()> {
        // PE file alignment (512 bytes)
        assert_eq!(align_to(1000, 512), 1024);
        assert_eq!(align_to(512, 512), 512); // Already aligned

        // PE section alignment (4096 bytes)
        assert_eq!(align_to(5000, 4096), 8192);
        assert_eq!(align_to(4096, 4096), 4096); // Already aligned

        // Data structure alignment (16 bytes)
        assert_eq!(align_to(100, 16), 112);
        assert_eq!(align_to(128, 16), 128); // Already aligned
        Ok(())
    }
}

//! ECMA-335 compressed integer encoding and decoding utilities.
//!
//! The size of an ECMA-335 compressed unsigned integer, which .NET metadata uses
//! to encode frequently-small values while supporting the full u32 range. The
//! encoder and decoder are [`crate::io::write_compressed_uint`] and
//! [`crate::io::read_compressed_uint`].
//!
//! # ECMA-335 Compressed Integer Format
//!
//! The compressed integer format uses variable-length encoding based on value magnitude:
//!
//! | Value Range     | Bytes | Encoding Pattern                    |
//! |-----------------|-------|-------------------------------------|
//! | 0x00-0x7F       | 1     | `0xxxxxxx`                         |
//! | 0x80-0x3FFF     | 2     | `10xxxxxx xxxxxxxx`                |
//! | 0x4000-0x1FFFFFFF | 4   | `110xxxxx xxxxxxxx xxxxxxxx xxxxxxxx` |
//!
//! # Examples
//!
//! ```no_run
//! use dotscope::io::{compressed_uint_size, write_compressed_uint};
//!
//! let mut buffer = Vec::new();
//!
//! // Small value (1 byte)
//! write_compressed_uint(42, &mut buffer)?;
//! assert_eq!(buffer, vec![0x2A]);
//! assert_eq!(compressed_uint_size(42), 1);
//!
//! buffer.clear();
//!
//! // Medium value (2 bytes)
//! write_compressed_uint(300, &mut buffer)?;
//! assert_eq!(buffer.len(), 2);
//! assert_eq!(compressed_uint_size(300), 2);
//!
//! buffer.clear();
//!
//! // Large value (4 bytes)
//! write_compressed_uint(70000, &mut buffer)?;
//! assert_eq!(buffer.len(), 4);
//! assert_eq!(compressed_uint_size(70000), 4);
//! ```

// ECMA-335 compressed integer encoding thresholds
/// Maximum value encodable in a single byte (0xxxxxxx pattern)
const SINGLE_BYTE_MAX: u32 = 0x7F;
/// Maximum value encodable in two bytes (10xxxxxx pattern)
const TWO_BYTE_MAX: u32 = 0x3FFF;

/// Calculates the encoded size of a compressed unsigned integer without encoding it.
///
/// This function determines how many bytes would be required to encode the given value
/// using ECMA-335 compressed integer encoding, without actually performing the encoding.
/// This is essential for layout planning where precise size calculations are needed.
///
/// # Arguments
///
/// * `value` - The unsigned integer value to calculate the encoded size for
///
/// # Returns
///
/// Returns the number of bytes as [`u64`] required to encode the value:
/// - `1` for values in range 0x00-0x7F
/// - `2` for values in range 0x80-0x3FFF  
/// - `4` for values in range 0x4000 and above
///
/// # Examples
///
/// ```no_run
/// use dotscope::io::compressed_uint_size;
///
/// assert_eq!(compressed_uint_size(42), 1);
/// assert_eq!(compressed_uint_size(300), 2);
/// assert_eq!(compressed_uint_size(70000), 4);
/// ```
pub fn compressed_uint_size(value: usize) -> u64 {
    if value <= SINGLE_BYTE_MAX as usize {
        1
    } else if value <= TWO_BYTE_MAX as usize {
        2
    } else {
        4
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::write_compressed_uint;

    #[test]
    fn test_compressed_uint_single_byte() {
        let mut buffer = Vec::new();
        write_compressed_uint(0, &mut buffer).unwrap();
        assert_eq!(buffer, vec![0x00]);

        buffer.clear();
        write_compressed_uint(127, &mut buffer).unwrap();
        assert_eq!(buffer, vec![0x7F]);
    }

    #[test]
    fn test_compressed_uint_two_bytes() {
        let mut buffer = Vec::new();
        write_compressed_uint(128, &mut buffer).unwrap();
        assert_eq!(buffer, vec![0x80, 0x80]);

        buffer.clear();
        write_compressed_uint(0x3FFF, &mut buffer).unwrap();
        assert_eq!(buffer, vec![0xBF, 0xFF]);
    }

    #[test]
    fn test_compressed_uint_four_bytes() {
        let mut buffer = Vec::new();
        write_compressed_uint(0x4000, &mut buffer).unwrap();
        assert_eq!(buffer, vec![0xC0, 0x00, 0x40, 0x00]);

        buffer.clear();
        write_compressed_uint(0x12345678, &mut buffer).unwrap();
        assert_eq!(buffer, vec![0xD2, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_compressed_uint_size() {
        assert_eq!(compressed_uint_size(0), 1);
        assert_eq!(compressed_uint_size(127), 1);
        assert_eq!(compressed_uint_size(128), 2);
        assert_eq!(compressed_uint_size(0x3FFF), 2);
        assert_eq!(compressed_uint_size(0x4000), 4);
        assert_eq!(compressed_uint_size(0xFFFFFFFF), 4);
    }

    #[test]
    fn test_size_consistency() {
        // Verify size calculation matches actual encoding
        let test_values = [0, 1, 127, 128, 300, 0x3FFF, 0x4000, 70000, 0x12345678];

        for value in test_values {
            let predicted_size = compressed_uint_size(value as usize);

            let mut buffer = Vec::new();
            write_compressed_uint(value, &mut buffer).unwrap();
            let actual_size = buffer.len() as u64;

            assert_eq!(
                predicted_size, actual_size,
                "Size mismatch for value {value}: predicted {predicted_size}, actual {actual_size}"
            );
        }
    }
}

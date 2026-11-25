//! Base64 encoding and decoding utilities.
//!
//! This module provides dependency-free Base64 encoding and decoding functions
//! that match the behavior of .NET's `System.Convert.ToBase64String` and
//! `System.Convert.FromBase64String`.

/// Encodes binary data to a Base64 string.
///
/// This is a simple, dependency-free implementation of Base64 encoding that matches
/// the output of `System.Convert.ToBase64String`.
///
/// # Arguments
///
/// * `data` - The bytes to encode
///
/// # Returns
///
/// A Base64-encoded string with padding.
///
/// # Examples
///
/// The `examples::base64_encode_example` test in this module runs this example.
#[must_use]
pub fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    let mut i: usize = 0;

    while i < data.len() {
        // Safe: loop condition guarantees i < data.len()
        let b0 = data.get(i).copied().unwrap_or(0);
        let b1 = data.get(i.saturating_add(1)).copied().unwrap_or(0);
        let b2 = data.get(i.saturating_add(2)).copied().unwrap_or(0);

        let n = u32::from(b0) << 16 | u32::from(b1) << 8 | u32::from(b2);

        // ALPHABET has 64 entries; mask `& 0x3F` keeps the index in [0, 63].
        let idx0 = ((n >> 18) & 0x3F) as usize;
        let idx1 = ((n >> 12) & 0x3F) as usize;
        result.push(char::from(ALPHABET.get(idx0).copied().unwrap_or(b'A')));
        result.push(char::from(ALPHABET.get(idx1).copied().unwrap_or(b'A')));

        if i.saturating_add(1) < data.len() {
            let idx2 = ((n >> 6) & 0x3F) as usize;
            result.push(char::from(ALPHABET.get(idx2).copied().unwrap_or(b'A')));
        } else {
            result.push('=');
        }

        if i.saturating_add(2) < data.len() {
            let idx3 = (n & 0x3F) as usize;
            result.push(char::from(ALPHABET.get(idx3).copied().unwrap_or(b'A')));
        } else {
            result.push('=');
        }

        i = i.saturating_add(3);
    }

    result
}

/// Decodes a Base64 string to binary data.
///
/// This is a simple, dependency-free implementation of Base64 decoding that matches
/// the behavior of `System.Convert.FromBase64String`.
///
/// # Arguments
///
/// * `s` - The Base64-encoded string to decode
///
/// # Returns
///
/// `Some(Vec<u8>)` on successful decode, `None` if the input is invalid Base64.
///
/// # Examples
///
/// The `examples::base64_decode_example` test in this module runs this example.
#[must_use]
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const DECODE_TABLE: [i8; 128] = [
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
        -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1,
        -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
        46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    ];

    let s = s.trim();
    if s.is_empty() {
        return Some(Vec::new());
    }

    let mut result = Vec::new();
    let bytes: Vec<u8> = s.bytes().filter(|&b| b != b'\n' && b != b'\r').collect();

    if !bytes.len().is_multiple_of(4) {
        return None;
    }

    let mut i: usize = 0;
    while i < bytes.len() {
        let mut n: u32 = 0;
        let mut pad_count: u32 = 0;

        // Pre-computed shifts so we don't perform `18 - j * 6` arithmetic at runtime.
        const SHIFTS: [u32; 4] = [18, 12, 6, 0];
        for (j, &shift) in SHIFTS.iter().enumerate() {
            // Safe: i + j < bytes.len() because length is multiple of 4
            // and i is incremented in steps of 4 within `i < bytes.len()`.
            let idx = i.checked_add(j)?;
            let b = *bytes.get(idx)?;
            if b == b'=' {
                pad_count = pad_count.saturating_add(1);
                continue;
            }
            if b >= 128 {
                return None;
            }
            let val = *DECODE_TABLE.get(usize::from(b))?;
            if val < 0 {
                return None;
            }
            // val is checked to be >= 0, so casting to u32 is safe
            // Sign loss is intentional: we've validated val >= 0
            #[allow(clippy::cast_sign_loss)]
            let val_u32 = val as u32;
            n |= val_u32 << shift;
        }

        // Truncation to u8 is intentional - we're extracting individual bytes
        #[allow(clippy::cast_possible_truncation)]
        {
            result.push((n >> 16) as u8);
            if pad_count < 2 {
                result.push((n >> 8) as u8);
            }
            if pad_count < 1 {
                result.push(n as u8);
            }
        }

        i = i.saturating_add(4);
    }

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b"Hello"), "SGVsbG8=");
        assert_eq!(base64_encode(b"Hello, World!"), "SGVsbG8sIFdvcmxkIQ==");
        assert_eq!(base64_encode(b""), "");
    }

    #[test]
    fn test_base64_decode() {
        assert_eq!(base64_decode("SGVsbG8="), Some(b"Hello".to_vec()));
        assert_eq!(
            base64_decode("SGVsbG8sIFdvcmxkIQ=="),
            Some(b"Hello, World!".to_vec())
        );
        assert_eq!(base64_decode(""), Some(Vec::new()));
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64_decode_invalid() {
        // Invalid character
        assert_eq!(base64_decode("SGVs!G8="), None);
        // Wrong length (not multiple of 4)
        assert_eq!(base64_decode("SGVsbG8"), None);
    }
}

#[cfg(test)]
mod examples {
    use super::*;
    use crate::Result;

    #[test]
    fn base64_encode_example() -> Result<()> {
        assert_eq!(base64_encode(b"Hello"), "SGVsbG8=");
        assert_eq!(base64_encode(b"Hello, World!"), "SGVsbG8sIFdvcmxkIQ==");
        Ok(())
    }

    #[test]
    fn base64_decode_example() -> Result<()> {
        assert_eq!(base64_decode("SGVsbG8="), Some(b"Hello".to_vec()));
        assert_eq!(
            base64_decode("SGVsbG8sIFdvcmxkIQ=="),
            Some(b"Hello, World!".to_vec())
        );
        Ok(())
    }
}

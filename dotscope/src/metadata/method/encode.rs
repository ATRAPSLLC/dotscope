//! Method body encoding utilities according to ECMA-335.
//!
//! This module provides functions for encoding method bodies and related structures
//! according to the ECMA-335 specification. It handles both tiny and fat format
//! method body headers as defined in II.25.4.5.

use crate::Result;

/// Encode method body header according to ECMA-335 II.25.4.5.
///
/// This function creates the appropriate method body header format (tiny or fat)
/// based on the method characteristics. The format is automatically selected:
///
/// - **Tiny Format**: Used when code size ≤ 63 bytes, max_stack ≤ 8,
///   no local variables, and no exception handlers
/// - **Fat Format**: Used for all other methods
///
/// # Arguments
///
/// * `code_size` - Size of the method's CIL bytecode in bytes
/// * `max_stack` - Maximum evaluation stack depth required
/// * `local_var_sig_tok` - Token for local variable signature (0 if no locals)
/// * `has_exceptions` - Whether the method has exception handlers
/// * `init_locals` - Whether to initialize local variables to zero
///
/// # Returns
///
/// The encoded method body header bytes (1 byte for tiny, 12 bytes for fat).
///
/// # Errors
///
/// Returns an error if encoding parameters are invalid or out of range.
///
/// # Examples
///
/// ```rust
/// # use dotscope::metadata::method::encode_method_body_header;
/// // Simple method with no locals or exceptions
/// let header = encode_method_body_header(2, 1, 0, false, false)?;
/// assert_eq!(header.len(), 1); // Tiny format
///
/// // Complex method requiring fat format
/// let header = encode_method_body_header(100, 16, 0x11000001, true, true)?;
/// assert_eq!(header.len(), 12); // Fat format
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Format Details
///
/// ## Tiny Format (1 byte)
/// ```text
/// Bits 7-2: Code size (6 bits, max 63)
/// Bits 1-0: Format flags (0x02 for tiny format)
/// ```
///
/// ## Fat Format (12 bytes)
/// ```text
/// Bytes 0-1: Flags (format=3, more_sects, init_locals)
/// Bytes 2-3: Max stack depth
/// Bytes 4-7: Code size
/// Bytes 8-11: Local variable signature token
/// ```
pub fn encode_method_body_header(
    code_size: u32,
    max_stack: u16,
    local_var_sig_tok: u32,
    has_exceptions: bool,
    init_locals: bool,
) -> Result<Vec<u8>> {
    // The tiny format when it can say all of it: at most 63 bytes of code, a stack of 8, no
    // locals, no exception sections and no InitLocals, which also zeroes `localloc` memory
    if code_size <= 63
        && max_stack <= 8
        && local_var_sig_tok == 0
        && !has_exceptions
        && !init_locals
    {
        // Tiny format: 1 byte header
        let header = u8::try_from((code_size << 2) | 0x02)
            .map_err(|_| malformed_error!("Method body header value exceeds u8 range"))?;
        Ok(vec![header])
    } else {
        // Fat format: 12 byte header
        let mut header = Vec::with_capacity(12);

        // Flags layout (ECMA-335 II.25.4.4):
        // Bits 0-1: Format (0x03 for fat)
        // Bit 3: CorILMethod_MoreSects (0x08)
        // Bit 4: CorILMethod_InitLocals (0x10)
        // Bits 12-15: Size in dwords (3 for fat header = 12 bytes)
        let mut flags: u16 = 0x3003; // Size (3 << 12) | FAT_FORMAT (0x03)
        if has_exceptions {
            flags |= 0x0008; // MORE_SECTS
        }
        if init_locals {
            flags |= 0x0010; // INIT_LOCALS
        }
        header.extend_from_slice(&flags.to_le_bytes());

        // Max stack (2 bytes)
        header.extend_from_slice(&max_stack.to_le_bytes());

        // Code size (4 bytes)
        header.extend_from_slice(&code_size.to_le_bytes());

        // Local var sig token (4 bytes)
        header.extend_from_slice(&local_var_sig_tok.to_le_bytes());

        Ok(header)
    }
}

#[cfg(test)]
mod tests {
    use proptest::{prelude::*, prop_assert_eq, test_runner::TestCaseError};

    use super::*;
    use crate::{metadata::method::body::MethodBody, testkit::arb::check};

    #[test]
    fn test_tiny_format_encoding() -> Result<()> {
        let header = encode_method_body_header(2, 1, 0, false, false)?;

        // Should be 1 byte for tiny format
        assert_eq!(header.len(), 1);

        // Create a complete method body with dummy code and verify it parses correctly
        let dummy_code = vec![0x17, 0x2A]; // ldc.i4.1, ret
        let mut method_body = header;
        method_body.extend_from_slice(&dummy_code);

        // Parse the method body and verify the header was encoded correctly
        let parsed = MethodBody::from(&method_body)?;
        assert_eq!(parsed.size_code, 2);
        assert_eq!(parsed.size_header, 1);
        assert_eq!(parsed.max_stack, 8); // Tiny format always has max_stack = 8
        assert_eq!(parsed.local_var_sig_token, 0);
        assert!(!parsed.is_fat);
        assert!(!parsed.is_exception_data);

        Ok(())
    }

    #[test]
    fn test_fat_format_encoding() -> Result<()> {
        let header = encode_method_body_header(100, 16, 0x11000001, false, true)?;

        // Should be 12 bytes for fat format
        assert_eq!(header.len(), 12);

        // Create a complete method body with dummy code and verify it parses correctly
        let dummy_code = vec![0x00; 100]; // 100 bytes of nop instructions
        let mut method_body = header;
        method_body.extend_from_slice(&dummy_code);

        // Parse the method body and verify the header was encoded correctly
        let parsed = MethodBody::from(&method_body)?;
        assert_eq!(parsed.size_code, 100);
        assert_eq!(parsed.size_header, 12);
        assert_eq!(parsed.max_stack, 16);
        assert_eq!(parsed.local_var_sig_token, 0x11000001);
        assert!(parsed.is_fat);
        assert!(!parsed.is_exception_data); // We set has_exceptions=false
        assert!(parsed.is_init_local); // We set init_locals=true

        Ok(())
    }

    #[test]
    fn test_fat_format_without_exceptions() -> Result<()> {
        let header = encode_method_body_header(70, 12, 0x11000002, false, true)?;

        // Create a complete method body with dummy code
        let dummy_code = vec![0x00; 70]; // 70 bytes of nop instructions
        let mut method_body = header;
        method_body.extend_from_slice(&dummy_code);

        // Parse the method body and verify the header was encoded correctly
        let parsed = MethodBody::from(&method_body)?;
        assert_eq!(parsed.size_code, 70);
        assert_eq!(parsed.size_header, 12);
        assert_eq!(parsed.max_stack, 12);
        assert_eq!(parsed.local_var_sig_token, 0x11000002);
        assert!(parsed.is_fat);
        assert!(!parsed.is_exception_data); // We set has_exceptions=false

        Ok(())
    }

    #[test]
    fn test_format_selection() -> Result<()> {
        // Tiny format conditions (init_locals ignored for tiny format)
        assert_eq!(encode_method_body_header(63, 8, 0, false, false)?.len(), 1);

        // Fat format triggers
        assert_eq!(encode_method_body_header(64, 8, 0, false, true)?.len(), 12); // code_size > 63
        assert_eq!(encode_method_body_header(63, 9, 0, false, true)?.len(), 12); // max_stack > 8
        assert_eq!(encode_method_body_header(63, 8, 1, false, true)?.len(), 12); // has locals
        assert_eq!(encode_method_body_header(63, 8, 0, true, true)?.len(), 12); // has exceptions

        Ok(())
    }

    #[test]
    fn test_fat_format_exception_flag() -> Result<()> {
        // Test that the exception flag is properly encoded in the header
        // Use code_size > 63 to force fat format regardless of other parameters
        let header_with_exceptions = encode_method_body_header(100, 5, 0, true, true)?;
        let header_without_exceptions = encode_method_body_header(100, 5, 0, false, true)?;

        // Both should be fat format (12 bytes)
        assert_eq!(header_with_exceptions.len(), 12);
        assert_eq!(header_without_exceptions.len(), 12);

        // The flags should differ - check the more_sects bit (bit 3) in the flags
        let flags_with = u16::from_le_bytes([header_with_exceptions[0], header_with_exceptions[1]]);
        let flags_without =
            u16::from_le_bytes([header_without_exceptions[0], header_without_exceptions[1]]);

        // Bit 3 (0x0008) should be set when has_exceptions=true
        assert_eq!(flags_with & 0x0008, 0x0008); // Should have more_sects bit set
        assert_eq!(flags_without & 0x0008, 0x0000); // Should not have more_sects bit set

        Ok(())
    }

    #[test]
    fn test_fat_format_init_locals_flag() -> Result<()> {
        // Test that the init_locals flag is properly encoded in the header
        let header_with_init = encode_method_body_header(100, 5, 0, false, true)?;
        let header_without_init = encode_method_body_header(100, 5, 0, false, false)?;

        // Both should be fat format (12 bytes)
        assert_eq!(header_with_init.len(), 12);
        assert_eq!(header_without_init.len(), 12);

        // The flags should differ - check the init_locals bit (bit 4) in the flags
        let flags_with = u16::from_le_bytes([header_with_init[0], header_with_init[1]]);
        let flags_without = u16::from_le_bytes([header_without_init[0], header_without_init[1]]);

        // Bit 4 (0x0010) should be set when init_locals=true
        assert_eq!(flags_with & 0x0010, 0x0010); // Should have init_locals bit set
        assert_eq!(flags_without & 0x0010, 0x0000); // Should not have init_locals bit set

        Ok(())
    }

    #[test]
    fn test_tiny_format_boundary_conditions() -> Result<()> {
        // Test exactly at the boundary of tiny format
        let header = encode_method_body_header(63, 8, 0, false, false)?;
        let dummy_code = vec![0x00; 63]; // Exactly 63 bytes
        let mut method_body = header;
        method_body.extend_from_slice(&dummy_code);

        let parsed = MethodBody::from(&method_body)?;
        assert_eq!(parsed.size_code, 63);
        assert!(!parsed.is_fat);
        assert_eq!(parsed.max_stack, 8);

        Ok(())
    }

    #[test]
    fn test_real_method_simulation() -> Result<()> {
        // Simulate a real simple method: ldc.i4.1; ret;
        let code = vec![0x17, 0x2A]; // ldc.i4.1, ret
        let header = encode_method_body_header(code.len() as u32, 1, 0, false, false)?;

        let mut method_body = header;
        method_body.extend_from_slice(&code);

        // Parse and verify it's correct
        let parsed = MethodBody::from(&method_body)?;
        assert_eq!(parsed.size_code, 2);
        assert!(!parsed.is_fat);
        assert_eq!(parsed.max_stack, 8); // Tiny format max stack
        assert_eq!(parsed.local_var_sig_token, 0);
        assert!(!parsed.is_exception_data);

        Ok(())
    }

    /// Every header decodes to what it was encoded from: the code size, the locals, the
    /// `InitLocals` flag, and the stack depth, which a tiny header states as 8.
    #[test]
    fn every_header_decodes_to_what_was_encoded() {
        let header = (
            prop_oneof![0u32..64, 64u32..300],
            prop_oneof![0u16..=8, any::<u16>()],
            prop_oneof![Just(0u32), Just(0x1100_0001)],
            any::<bool>(),
        );
        check(header, |(code_size, max_stack, locals, init_locals)| {
            let mut body =
                encode_method_body_header(code_size, max_stack, locals, false, init_locals)
                    .map_err(|error| TestCaseError::fail(format!("does not encode: {error}")))?;
            body.resize(body.len() + code_size as usize, 0x00);
            let decoded = MethodBody::from(&body)
                .map_err(|error| TestCaseError::fail(format!("does not decode: {error}")))?;
            prop_assert_eq!(decoded.size_code, code_size as usize);
            prop_assert_eq!(decoded.local_var_sig_token, locals);
            prop_assert_eq!(decoded.is_init_local, init_locals);
            let stack = if decoded.is_fat {
                usize::from(max_stack)
            } else {
                8
            };
            prop_assert_eq!(decoded.max_stack, stack);
            Ok(())
        });
    }
}

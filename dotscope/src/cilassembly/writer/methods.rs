//! Method body writer for direct output serialization.
//!
//! This module provides functionality to write method bodies directly to output,
//! handling both tiny and fat header formats, IL code, and exception handlers.
//!
//! # Method Body Format
//!
//! .NET methods have two header formats (ECMA-335 §II.25.4):
//!
//! ## Tiny Format (1 byte header)
//! - Code size ≤ 63 bytes
//! - Max stack = 8 (implied)
//! - No local variables
//! - No exception handlers
//!
//! ## Fat Format (12 byte header)
//! - Code size up to 4GB
//! - Configurable max stack
//! - Local variable signature token
//! - Optional exception handler sections
//!
//! # Exception Handler Sections
//!
//! Exception handlers follow the method code with 4-byte alignment:
//! - **Tiny sections**: 12 bytes per handler (for small offsets)
//! - **Fat sections**: 24 bytes per handler (for large offsets)
//!
//! # IL Token Patching
//!
//! When heaps or tables are rebuilt, IL instructions containing tokens must be patched
//! to reference the new offsets. This module provides [`patch_il_tokens`] which handles:
//!
//! - `ldstr` (0x72): UserString heap references
//! - `call`, `callvirt`, `newobj`, etc.: Metadata table tokens
//!
//! The patching uses remapping tables to translate old token values to new ones.

use std::collections::HashMap;

use crate::{
    assembly::{decode_stream, Operand},
    cilassembly::{
        changes::ChangeRef,
        writer::{output::Output, remapper::TokenRemap},
        AssemblyChanges,
    },
    metadata::{
        method::{ExceptionHandlerFlags, MethodBody},
        tables::TableId,
        token::Token,
    },
    Error, Parser, Referrer, Result,
};

/// UserString heap table ID (0x70) - used in ldstr tokens.
const USERSTRING_TABLE_ID: u8 = 0x70;

/// UserString placeholder ID (0xF0 = 0x70 | 0x80) - indicates unresolved UserString.
const USERSTRING_PLACEHOLDER_ID: u8 = 0xF0;

/// Writes a method body to output at the specified offset.
///
/// Serializes the method header (tiny or fat), IL code, and exception handlers
/// directly to the output file using the [`MethodBody::write_to`] method.
///
/// # Arguments
///
/// * `output` - The memory-mapped output file to write to
/// * `offset` - The file offset where the method body should start (must be 4-byte aligned for fat headers)
/// * `body` - The method body to serialize
/// * `il_code` - The IL bytecode for the method
///
/// # Returns
///
/// The total number of bytes written (header + code + exception handlers + padding).
///
/// # Errors
///
/// Returns an error if writing to the output fails.
pub fn write_method_body(
    output: &mut Output,
    offset: u64,
    body: &MethodBody,
    il_code: &[u8],
) -> Result<u64> {
    // Fat headers require 4-byte alignment
    let start_pos = if body.is_fat {
        offset.saturating_add(3) & !3u64
    } else {
        offset
    };

    // Use the OutputWriter to stream directly to the memory-mapped file
    let mut writer = output.writer_at(start_pos);
    let bytes_written = body.write_to(&mut writer, il_code)?;

    Ok(bytes_written)
}

/// Remaps IL tokens in place using decode-and-patch approach.
///
/// This function handles all token transformations in IL bytecode:
/// - **Token remapping**: Updates tokens when metadata table rows are deleted/shifted
/// - **UserString remapping**: Updates ldstr tokens when the UserString heap changes
/// - **Placeholder resolution**: Resolves placeholder tokens in newly created methods
///
/// The function decodes instructions to find token positions, then patches the token
/// values directly in the byte slice. Since tokens are always 4 bytes, this preserves
/// the exact size and structure of the IL code.
///
/// # Arguments
///
/// * `il_bytes` - The raw IL instruction bytes (modified in place)
/// * `method` - The method whose body this is, as the input assembly numbers it
/// * `tokens` - How metadata tokens are renumbered (for row deletions)
/// * `userstring_map` - Maps old UserString offsets to new offsets
/// * `changes` - Assembly changes for resolving placeholders (can be None if not needed)
///
/// # Errors
///
/// Returns an error if IL decoding fails, or [`Error::DanglingReference`] when an
/// instruction names a row the write deletes.
pub fn remap_il_tokens(
    il_bytes: &mut [u8],
    method: Token,
    tokens: &TokenRemap,
    userstring_map: &HashMap<u32, u32>,
    changes: Option<&AssemblyChanges>,
) -> Result<()> {
    if il_bytes.is_empty() {
        return Ok(());
    }

    // Decode IL bytes into instructions (includes offset information)
    let mut parser = Parser::new(il_bytes);
    let instructions = decode_stream(&mut parser, 0)?;

    // Find and patch token operands in place
    for instr in &instructions {
        if let Operand::Token(token) = &instr.operand {
            let token_value = token.value();
            let table_id = token_value >> 24;
            let row = token_value & 0x00FF_FFFF;

            let new_token_value = if ChangeRef::is_placeholder(row) {
                // Check for placeholder tokens (row >= 0x800000)
                changes
                    .and_then(|c| c.lookup_by_placeholder(row))
                    .and_then(|cr| cr.token())
                    .map(|t| t.value())
            } else if table_id == u32::from(USERSTRING_TABLE_ID) {
                // Check for UserString tokens (table ID 0x70 for UserString heap)
                let offset = token_value & 0x00FF_FFFF;
                userstring_map.get(&offset).map(|&new_offset| {
                    (u32::from(USERSTRING_TABLE_ID) << 24) | (new_offset & 0x00FF_FFFF)
                })
            } else if table_id == u32::from(USERSTRING_PLACEHOLDER_ID) {
                // Check for UserString placeholder (0xF0 = 0x70 | 0x80 high bit)
                if let Some(changes) = changes {
                    let offset_part = token_value & 0x00FF_FFFF;
                    let heap_placeholder = 0x8000_0000 | offset_part;
                    if let Some(change_ref) = changes.lookup_by_placeholder(heap_placeholder) {
                        change_ref.offset().map(|actual_offset| {
                            (u32::from(USERSTRING_TABLE_ID) << 24) | (actual_offset & 0x00FF_FFFF)
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                // Regular token remapping
                let new = tokens.remap(Referrer::Body(method), token_value)?;
                (new != token_value).then_some(new)
            };

            if let Some(new_value) = new_token_value {
                // Calculate the byte offset of the token operand
                // Token operand is the last 4 bytes of the instruction
                // Safe: CIL method body offsets fit in usize
                #[allow(clippy::cast_possible_truncation)]
                let instr_offset = instr.offset as usize;
                #[allow(clippy::cast_possible_truncation)]
                let instr_size = instr.size as usize;
                if let Some(instr_end) = instr_offset.checked_add(instr_size) {
                    if let Some(token_offset) = instr_end.checked_sub(4) {
                        if let Some(dest) = il_bytes.get_mut(token_offset..instr_end) {
                            dest.copy_from_slice(&new_value.to_le_bytes());
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Rebuilds a method body by parsing, remapping tokens, and re-serializing.
///
/// This encapsulates the full parse → remap → rebuild cycle for CIL method bodies.
/// It handles both original methods (from the input assembly) and newly created
/// methods (from assembly changes with placeholder tokens).
///
/// # Process
///
/// 1. Parse the method body header (with lenient fallback for malformed EH)
/// 2. Extract IL bytecode
/// 3. Remap IL tokens (metadata tokens, UserString references, placeholders)
/// 4. Remap `local_var_sig_token` (placeholder resolution + token remapping)
/// 5. Remap exception handler catch type tokens
/// 6. Rebuild via `write_to()`, returning the complete method body bytes
///
/// # Arguments
///
/// * `body_data` - Raw bytes starting at the method body header
/// * `method` - The method whose body this is, as the input assembly numbers it
/// * `tokens` - How metadata tokens are renumbered (for row deletions/shifts)
/// * `userstring_map` - Maps old UserString offsets to new offsets
/// * `changes` - Assembly changes for resolving placeholder tokens (None for original methods)
///
/// # Returns
///
/// The rebuilt method body as a byte vector (header + IL code + exception handlers).
///
/// # Errors
///
/// Returns an error if method body parsing or IL decoding fails, or
/// [`Error::DanglingReference`] when the body names a row the write deletes.
pub fn rebuild_method_body(
    body_data: &[u8],
    method: Token,
    tokens: &TokenRemap,
    userstring_map: &HashMap<u32, u32>,
    changes: Option<&AssemblyChanges>,
) -> Result<Vec<u8>> {
    // Parse method body with lenient
    let mut body = match MethodBody::from_lenient(body_data) {
        Ok((b, _)) => b,
        Err(e) => return Err(e),
    };

    // Extract IL code from the body data
    let il_end = body
        .size_header
        .checked_add(body.size_code)
        .ok_or_else(|| Error::LayoutFailed("Method body IL end offset overflow".to_string()))?;
    let mut il_code = body_data
        .get(body.size_header..il_end)
        .ok_or_else(|| Error::LayoutFailed("Method body IL slice out of bounds".to_string()))?
        .to_vec();

    // Remap IL tokens (metadata tokens, UserString references, placeholders)
    remap_il_tokens(&mut il_code, method, tokens, userstring_map, changes)?;

    // Remap local_var_sig_token
    if body.local_var_sig_token != 0 {
        // Resolve placeholder tokens (for newly created methods)
        if let Some(changes) = changes {
            let table_id = body.local_var_sig_token >> 24;
            let row_id = body.local_var_sig_token & 0x00FF_FFFF;

            if table_id == u32::from(TableId::StandAloneSig.token_type())
                && ChangeRef::is_placeholder(row_id)
            {
                if let Some(change_ref) = changes.lookup_by_placeholder(row_id) {
                    if let Some(resolved_token) = change_ref.token() {
                        body.local_var_sig_token = resolved_token.value();
                    }
                }
            }
        }

        // Apply token remapping
        body.local_var_sig_token =
            tokens.remap(Referrer::Body(method), body.local_var_sig_token)?;
    }

    // Remap exception handler catch type tokens
    for handler in &mut body.exception_handlers {
        if handler.flags == ExceptionHandlerFlags::EXCEPTION && handler.filter_offset != 0 {
            handler.filter_offset = tokens.remap(Referrer::Body(method), handler.filter_offset)?;
        }
    }

    // Rebuild method body
    let mut rebuilt = Vec::new();
    body.write_to(&mut rebuilt, &il_code)?;

    Ok(rebuilt)
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read};

    use tempfile::tempdir;

    use super::*;

    /// The method the bodies under test belong to.
    const METHOD: Token = Token::new(0x0600_0001);

    #[test]
    fn test_write_tiny_method() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("test.bin");

        let mut output = Output::create(&path, 1024).unwrap();

        // Simple tiny method: ldarg.0 (0x02), ret (0x2A)
        let il_code = vec![0x02, 0x2A];
        let body = MethodBody {
            size_code: 2,
            size_header: 1,
            local_var_sig_token: 0,
            max_stack: 8,
            is_fat: false,
            is_init_local: false,
            is_exception_data: false,
            exception_handlers: vec![],
            exception_format: None,
        };

        let bytes_written = write_method_body(&mut output, 0, &body, &il_code).unwrap();
        assert_eq!(bytes_written, 3); // 1 header + 2 code

        output.finalize(None).unwrap();

        // Verify content
        let mut file = File::open(&path).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();

        // Header: (2 << 2) | 0x02 = 0x0A
        assert_eq!(contents[0], 0x0A);
        // Code
        assert_eq!(contents[1], 0x02);
        assert_eq!(contents[2], 0x2A);
    }

    #[test]
    fn test_write_fat_method() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("test.bin");

        let mut output = Output::create(&path, 1024).unwrap();

        // Fat method with some IL code
        let il_code = vec![0x00; 100]; // 100 nop instructions
        let body = MethodBody {
            size_code: 100,
            size_header: 12,
            local_var_sig_token: 0x11000001,
            max_stack: 8,
            is_fat: true,
            is_init_local: true,
            is_exception_data: false,
            exception_handlers: vec![],
            exception_format: None,
        };

        let bytes_written = write_method_body(&mut output, 0, &body, &il_code).unwrap();
        assert_eq!(bytes_written, 112); // 12 header + 100 code

        output.finalize(None).unwrap();

        // Parse back and verify
        let mut file = File::open(&path).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();

        let parsed = MethodBody::from(&contents).unwrap();
        assert!(parsed.is_fat);
        assert!(parsed.is_init_local);
        assert_eq!(parsed.size_code, 100);
        assert_eq!(parsed.max_stack, 8);
        assert_eq!(parsed.local_var_sig_token, 0x11000001);
    }

    /// Helper to read a 32-bit little-endian token from bytes.
    fn read_token_at(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    }

    #[test]
    fn test_remap_il_tokens_ldstr() {
        // ldstr with token 0x70000100 (UserString at offset 0x100)
        let mut il_bytes = vec![
            0x00, // nop
            0x72, 0x00, 0x01, 0x00, 0x70, // ldstr 0x70000100
            0x2A, // ret
        ];

        let mut userstring_map = HashMap::new();
        userstring_map.insert(0x100, 0x200); // Map offset 0x100 -> 0x200

        let token_map = TokenRemap::default();

        remap_il_tokens(&mut il_bytes, METHOD, &token_map, &userstring_map, None).unwrap();

        // Check that token was updated to 0x70000200
        let new_token = read_token_at(&il_bytes, 2);
        assert_eq!(new_token, 0x70000200);
    }

    #[test]
    fn test_remap_il_tokens_call() {
        // call with token 0x06000001 (MethodDef RID 1)
        let mut il_bytes = vec![
            0x00, // nop
            0x28, 0x01, 0x00, 0x00, 0x06, // call 0x06000001
            0x2A, // ret
        ];

        let userstring_map = HashMap::new();
        let mut token_map = TokenRemap::default();
        token_map.insert(0x06000001, 0x06000005); // Map method 1 -> method 5

        remap_il_tokens(&mut il_bytes, METHOD, &token_map, &userstring_map, None).unwrap();

        // Check that token was updated
        let new_token = read_token_at(&il_bytes, 2);
        assert_eq!(new_token, 0x06000005);
    }

    #[test]
    fn test_remap_il_tokens_multiple() {
        // Multiple instructions with tokens
        let mut il_bytes = vec![
            0x72, 0x00, 0x01, 0x00, 0x70, // ldstr 0x70000100
            0x28, 0x01, 0x00, 0x00, 0x06, // call 0x06000001
            0x6F, 0x02, 0x00, 0x00, 0x06, // callvirt 0x06000002
            0x2A, // ret
        ];

        let mut userstring_map = HashMap::new();
        userstring_map.insert(0x100, 0x200);

        let mut token_map = TokenRemap::default();
        token_map.insert(0x06000001, 0x06000010);
        token_map.insert(0x06000002, 0x06000020);

        remap_il_tokens(&mut il_bytes, METHOD, &token_map, &userstring_map, None).unwrap();

        // Check all tokens were updated
        assert_eq!(read_token_at(&il_bytes, 1), 0x70000200);
        assert_eq!(read_token_at(&il_bytes, 6), 0x06000010);
        assert_eq!(read_token_at(&il_bytes, 11), 0x06000020);
    }

    #[test]
    fn test_remap_il_tokens_no_match() {
        // Tokens that don't have mappings should be left unchanged
        let mut il_bytes = vec![
            0x72, 0x00, 0x01, 0x00, 0x70, // ldstr 0x70000100
            0x28, 0x01, 0x00, 0x00, 0x06, // call 0x06000001
            0x2A, // ret
        ];

        let userstring_map = HashMap::new(); // Empty - no mappings
        let token_map = TokenRemap::default(); // Empty - no mappings

        remap_il_tokens(&mut il_bytes, METHOD, &token_map, &userstring_map, None).unwrap();

        // Tokens should remain unchanged
        assert_eq!(read_token_at(&il_bytes, 1), 0x70000100);
        assert_eq!(read_token_at(&il_bytes, 6), 0x06000001);
    }

    #[test]
    fn test_remap_il_tokens_two_byte_opcode() {
        // sizeof with token 0x02000001 (TypeDef RID 1)
        // sizeof pushes the size of a type, so it doesn't require stack setup
        let mut il_bytes = vec![
            0x00, // nop
            0xFE, 0x1C, 0x01, 0x00, 0x00, 0x02, // sizeof 0x02000001
            0x26, // pop (discard the result)
            0x2A, // ret
        ];

        let userstring_map = HashMap::new();
        let mut token_map = TokenRemap::default();
        token_map.insert(0x02000001, 0x02000005);

        remap_il_tokens(&mut il_bytes, METHOD, &token_map, &userstring_map, None).unwrap();

        // Check token at offset 3 (after 0xFE 0x1C)
        let new_token = read_token_at(&il_bytes, 3);
        assert_eq!(new_token, 0x02000005);
    }
}

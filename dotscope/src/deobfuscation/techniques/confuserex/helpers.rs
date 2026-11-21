//! Shared utility functions for ConfuserEx technique modules.
//!
//! Consolidates helpers used by multiple ConfuserEx techniques:
//!
//! - [`find_encrypted_methods`] — identifies methods with encrypted bodies
//! - [`get_method_rva`] — reads a method's RVA from the MethodDef table
//! - [`extract_method_body_at_rva`] — parses a decrypted method body from memory
//! - [`get_field_data_size`] — determines FieldRVA data size via ClassLayout

use std::collections::HashSet;

use crate::{
    deobfuscation::utils::get_field_data_size,
    metadata::{
        method::MethodBody,
        tables::{FieldRvaRaw, ImplMapRaw, MethodDefRaw},
        token::Token,
    },
    CilObject,
};

/// Maximum bytes to read when extracting a method body from memory.
const MAX_METHOD_BODY_SIZE: usize = 65536;

/// Finds methods with encrypted bodies in the assembly.
///
/// These are methods where the RVA is set but the body couldn't be parsed,
/// indicating the method body is encrypted or corrupted.
pub fn find_encrypted_methods(assembly: &CilObject) -> Vec<Token> {
    assembly
        .methods()
        .iter()
        .filter_map(|entry| {
            let method = entry.value();
            if method.rva.is_some_and(|rva| rva > 0) && !method.has_body() {
                Some(method.token)
            } else {
                None
            }
        })
        .collect()
}

/// Returns all method tokens that have a non-zero RVA.
///
/// Includes both methods with valid bodies and encrypted methods. Used when
/// re-extracting all method bodies after anti-tamper decryption, since section
/// layout changes may invalidate existing RVAs.
pub fn find_all_methods_with_rva(assembly: &CilObject) -> Vec<Token> {
    assembly
        .methods()
        .iter()
        .filter_map(|entry| {
            let method = entry.value();
            if method.rva.is_some_and(|rva| rva > 0) {
                Some(method.token)
            } else {
                None
            }
        })
        .collect()
}

/// Gets the RVA for a method from the raw MethodDef table.
pub fn get_method_rva(assembly: &CilObject, token: Token) -> Option<u32> {
    let tables = assembly.tables()?;
    let method_table = tables.table::<MethodDefRaw>()?;
    let row = token.row();
    let method_row = method_table.get(row).ok().flatten()?;
    Some(method_row.rva)
}

/// Extracts a decrypted method body from a virtual image at the given RVA.
///
/// Reads bytes from the virtual image, parses the method body header to
/// validate and determine size, re-encodes to canonical format, and returns
/// the bytes ready for storage.
pub fn extract_method_body_at_rva(memory: &[u8], rva: u32) -> Option<Vec<u8>> {
    let rva_usize = rva as usize;
    if rva_usize >= memory.len() {
        return None;
    }

    let available = memory.len().saturating_sub(rva_usize);
    let read_size = available.min(MAX_METHOD_BODY_SIZE);
    let body_end = rva_usize.checked_add(read_size)?;
    let body_slice = memory.get(rva_usize..body_end)?;

    let body = MethodBody::from(body_slice).ok()?;

    let il_start = body.size_header;
    let il_end = il_start.checked_add(body.size_code)?;
    if il_end > body_slice.len() {
        return None;
    }
    let il_code = body_slice.get(il_start..il_end)?;

    let mut output = Vec::new();
    body.write_to(&mut output, il_code).ok()?;

    Some(output)
}

/// Extracts decrypted FieldRVA data from a virtual image.
///
/// Anti-tamper encrypts the Constants section alongside method bodies. This
/// function extracts all FieldRVA data entries from the decrypted virtual image.
///
/// Returns `(field_rid, original_rva, decrypted_data)` tuples plus a count of
/// fields that couldn't be extracted.
pub fn extract_decrypted_field_data(
    assembly: &CilObject,
    virtual_image: &[u8],
) -> (Vec<(u32, u32, Vec<u8>)>, usize) {
    let mut fields = Vec::new();
    let mut failed_count: usize = 0;

    let Some(tables) = assembly.tables() else {
        return (fields, failed_count);
    };
    let Some(fieldrva_table) = tables.table::<FieldRvaRaw>() else {
        return (fields, failed_count);
    };

    for row in fieldrva_table {
        let row = match row {
            Ok(row) => row,
            Err(e) => {
                log::warn!("skipping unreadable metadata row: {e}");
                continue;
            }
        };
        let rva = row.rva;
        if rva == 0 {
            continue;
        }

        let Some(field_size) = get_field_data_size(assembly, row.field) else {
            failed_count = failed_count.saturating_add(1);
            continue;
        };

        let rva_usize = rva as usize;
        let Some(end) = rva_usize.checked_add(field_size) else {
            failed_count = failed_count.saturating_add(1);
            continue;
        };
        let Some(slice) = virtual_image.get(rva_usize..end) else {
            failed_count = failed_count.saturating_add(1);
            continue;
        };

        let data = slice.to_vec();
        fields.push((row.rid, rva, data));
    }

    (fields, failed_count)
}

/// Finds methods that contain a call/callvirt to any token in `target_tokens`.
///
/// This supplements [`find_methods_calling_apis`](crate::deobfuscation::utils::find_methods_calling_apis)
/// for cases where the target is identified by token rather than name — e.g.,
/// P/Invoke MethodDef tokens resolved from the ImplMap table whose managed
/// names have been obfuscated.
///
/// # Returns
///
/// A [`HashSet`] of method tokens that call at least one of the target tokens.
pub fn find_methods_calling_tokens(
    assembly: &CilObject,
    target_tokens: &HashSet<Token>,
) -> HashSet<Token> {
    if target_tokens.is_empty() {
        return HashSet::new();
    }

    let mut callers = HashSet::new();
    for method_entry in assembly.methods() {
        let method = method_entry.value();
        for instr in method.instructions() {
            if let Some(token) = instr.get_token_operand() {
                if target_tokens.contains(&token) {
                    callers.insert(method.token);
                    break;
                }
            }
        }
    }
    callers
}

/// Resolves P/Invoke import names from the ImplMap table to find MethodDef
/// tokens that map to a specific DLL export.
///
/// ConfuserEx renames P/Invoke method definitions (e.g., "VirtualProtect" → "b"),
/// but the ImplMap table's `import_name` field always holds the real DLL export
/// name. This function scans ImplMap to build a set of MethodDef tokens whose
/// actual import name contains `target_name`.
pub fn resolve_pinvoke_tokens(assembly: &CilObject, target_name: &str) -> HashSet<Token> {
    let mut tokens = HashSet::new();

    let Some(tables) = assembly.tables() else {
        return tokens;
    };
    let Some(strings) = assembly.strings() else {
        return tokens;
    };
    let Some(implmap_table) = tables.table::<ImplMapRaw>() else {
        return tokens;
    };

    for row in implmap_table {
        let row = match row {
            Ok(row) => row,
            Err(e) => {
                log::warn!("skipping unreadable metadata row: {e}");
                continue;
            }
        };
        let Ok(import_name) = strings.get(row.import_name as usize) else {
            continue;
        };
        if import_name.contains(target_name) {
            // member_forwarded points to the MethodDef via coded index.
            tokens.insert(row.member_forwarded.token);
        }
    }

    tokens
}

#[cfg(test)]
mod tests {
    use crate::testkit::helpers::load_sample;

    #[test]
    fn test_find_encrypted_methods_on_antitamper() {
        let assembly = load_sample("packers/confuserex/1.6.0/mkaring_antitamper.exe");

        let encrypted = super::find_encrypted_methods(&assembly);
        assert!(
            !encrypted.is_empty(),
            "Anti-tamper sample should have encrypted method bodies"
        );
    }

    #[test]
    fn test_find_encrypted_methods_on_original() {
        let assembly = load_sample("packers/confuserex/1.6.0/original.exe");

        let encrypted = super::find_encrypted_methods(&assembly);
        assert!(
            encrypted.is_empty(),
            "Original sample should have no encrypted method bodies"
        );
    }

    #[test]
    fn test_find_all_methods_with_rva() {
        let assembly = load_sample("packers/confuserex/1.6.0/original.exe");

        let methods = super::find_all_methods_with_rva(&assembly);
        assert!(
            !methods.is_empty(),
            "Original sample should have methods with RVAs"
        );
    }

    #[test]
    fn test_resolve_pinvoke_tokens_on_maximum() {
        let assembly = load_sample("packers/confuserex/1.6.0/mkaring_maximum.exe");

        let vp_tokens = super::resolve_pinvoke_tokens(&assembly, "VirtualProtect");
        assert!(
            !vp_tokens.is_empty(),
            "Maximum preset should have VirtualProtect P/Invoke"
        );
    }

    #[test]
    fn test_resolve_pinvoke_tokens_on_original() {
        let assembly = load_sample("packers/confuserex/1.6.0/original.exe");

        let vp_tokens = super::resolve_pinvoke_tokens(&assembly, "VirtualProtect");
        assert!(
            vp_tokens.is_empty(),
            "Original sample should not have VirtualProtect P/Invoke"
        );
    }

    #[test]
    fn test_extract_method_body_at_rva_invalid() {
        // Empty memory should return None
        let result = super::extract_method_body_at_rva(&[], 0);
        assert!(result.is_none(), "Empty memory should return None");

        // RVA beyond memory bounds should return None
        let memory = vec![0u8; 16];
        let result = super::extract_method_body_at_rva(&memory, 100);
        assert!(result.is_none(), "Out-of-bounds RVA should return None");
    }
}

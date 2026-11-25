//! BitMono UnmanagedString detection and reversal technique.
//!
//! Detects and reverses BitMono's UnmanagedString protection, which replaces
//! string literals with calls to fake native methods. Each fake native method
//! is declared in `<Module>` with the `Native` code type flag and contains a
//! short x86/x64 code prefix followed by the raw string bytes at its RVA.
//!
//! # CIL Pattern
//!
//! Each string literal is replaced with:
//! ```text
//! call       <fake_native_method>     // Returns pointer to embedded bytes
//! newobj     string::.ctor(sbyte*)    // Or string::.ctor(char*), etc.
//! ```
//!
//! The fake native method body (at its RVA) contains:
//! - **x64**: `lea rax, [rip+1]; ret` (8 bytes) followed by string bytes
//! - **x86**: `call $+5; pop eax; add eax, <offset>; ret` (~20 bytes) followed
//!   by string bytes
//!
//! # Detection
//!
//! Finds methods in `<Module>` with `Native` impl code type that are BitMono's
//! fake P/Invoke stubs. Two variants are detected:
//! - **Older BitMono**: Native methods without `PINVOKE_IMPL` or `INTERNAL_CALL` flags
//! - **Newer BitMono**: Native methods with `PINVOKE_IMPL` flag but GUID-format names
//!   (e.g. `"260dce49-5827-4a3c-b8f1-1234567890ab"`)
//!
//! During detection the embedded strings are extracted from each native method
//! body using traversal-based x86 disassembly and stored in [`UnmanagedFindings`].
//!
//! # SSA Pass
//!
//! The reversal pass lives in [`crate::deobfuscation::passes::bitmono::unmanaged`]
//! and replaces `call <native>` + `newobj string::.ctor(ptr)` patterns with
//! `DecryptedString` constants, which the codegen pipeline emits as `ldstr`
//! instructions.

use std::{any::Any, collections::HashMap, sync::Arc};

use crate::{
    analysis::{x86_native_body_size, CilTarget},
    cilassembly::CleanupRequest,
    compiler::{CompilerContext, PassPhase, SsaPass},
    deobfuscation::{
        context::AnalysisContext,
        passes::bitmono::UnmanagedStringReversalPass,
        techniques::{Detection, Evidence, Technique, TechniqueCategory},
        utils::is_guid_name,
    },
    metadata::token::Token,
    utils::decode_utf16le,
    CilObject,
};

/// Findings from BitMono UnmanagedString detection.
#[derive(Debug)]
pub struct UnmanagedFindings {
    /// Tokens of fake native methods in `<Module>` containing embedded strings.
    pub native_methods: Vec<Token>,
    /// Extracted native_token -> decrypted_string mapping.
    pub string_map: Vec<(Token, String)>,
}

/// Detects and reverses BitMono's fake native string methods (UnmanagedString protection).
///
/// Identifies methods in `<Module>` with `Native` code type that are not
/// legitimate P/Invoke declarations. These contain embedded string data after
/// a short x86/x64 trampoline and are called via `call <native>` + `newobj
/// string::.ctor(ptr)` patterns at usage sites.
///
/// The detection phase also extracts the embedded strings from the native method
/// bodies so that [`create_pass`](Technique::create_pass) can build a fully
/// populated [`UnmanagedStringReversalPass`] without needing additional
/// byte-level preparation.
pub struct BitMonoUnmanaged;

impl Technique for BitMonoUnmanaged {
    fn id(&self) -> &'static str {
        "bitmono.unmanaged"
    }

    fn name(&self) -> &'static str {
        "BitMono UnmanagedString Reversal"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Value
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let types = assembly.types();
        let Some(module_type) = types.module_type() else {
            return Detection::new_empty();
        };

        let mut native_methods = Vec::new();

        for (_, method_ref) in module_type.methods.iter() {
            let Some(method) = method_ref.upgrade() else {
                continue;
            };

            if !method.is_code_native() {
                continue;
            }

            // Original check: native without PINVOKE (older BitMono versions)
            if !method.is_pinvoke() && !method.is_internal_call() {
                native_methods.push(method.token);
                continue;
            }

            // BitMono sets PINVOKE_IMPL on fake native methods but names them
            // with GUIDs. Real P/Invoke methods have meaningful API names.
            if is_guid_name(&method.name) {
                native_methods.push(method.token);
            }
        }

        if native_methods.is_empty() {
            return Detection::new_empty();
        }

        // Extract embedded strings from native method bodies.
        let is_64bit = assembly.file().is_pe32_plus_format().unwrap_or(false);
        let mut string_map = Vec::new();

        for native_token in &native_methods {
            if let Some(decrypted) = extract_native_string(assembly, *native_token, is_64bit) {
                string_map.push((*native_token, decrypted));
            }
        }

        let count = native_methods.len();
        let extracted = string_map.len();
        let mut evidence = vec![Evidence::Structural(format!(
            "{count} fake native methods in <Module> (BitMono UnmanagedString)"
        ))];
        if extracted > 0 {
            evidence.push(Evidence::Structural(format!(
                "{extracted} embedded strings extracted from native method bodies"
            )));
        }

        Detection::new_detected(
            evidence,
            Some(Box::new(UnmanagedFindings {
                native_methods,
                string_map,
            }) as Box<dyn Any + Send + Sync>),
        )
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        Some(PassPhase::Simplify)
    }

    fn create_pass(
        &self,
        _ctx: &AnalysisContext,
        detection: &Detection,
        _assembly: &Arc<CilObject>,
    ) -> Vec<Box<dyn SsaPass<CilTarget, CompilerContext>>> {
        let Some(findings) = detection.findings::<UnmanagedFindings>() else {
            return Vec::new();
        };
        if findings.string_map.is_empty() {
            return Vec::new();
        }
        let native_string_map: HashMap<Token, String> = findings
            .string_map
            .iter()
            .map(|(token, s)| (*token, s.clone()))
            .collect();
        vec![Box::new(UnmanagedStringReversalPass { native_string_map })]
    }

    fn cleanup(&self, detection: &Detection) -> Option<CleanupRequest> {
        let findings = detection.findings::<UnmanagedFindings>()?;
        if findings.native_methods.is_empty() {
            return None;
        }

        let mut request = CleanupRequest::new();
        for token in &findings.native_methods {
            request.add_method(*token);
        }
        Some(request)
    }
}

/// Extracts the embedded string from a fake native method body.
///
/// Locates the method's RVA in the PE file, uses traversal-based x86
/// disassembly ([`x86_native_body_size`]) to find where executable code ends,
/// then decodes the string bytes that follow. Both UTF-8/ASCII and UTF-16LE
/// encodings are attempted.
///
/// # Arguments
///
/// * `assembly` - The assembly containing the native method.
/// * `native_token` - Token of the fake native method to extract from.
/// * `is_64bit` - `true` if the PE is 64-bit (PE32+), which selects the
///   x64 disassembly variant for computing the native code prefix length.
///
/// # Returns
///
/// `Some(string)` if the embedded string was successfully located and decoded,
/// `None` if the method has no RVA, the offset is out of bounds, the native
/// code prefix is zero or covers all available bytes, or decoding fails.
fn extract_native_string(
    assembly: &CilObject,
    native_token: Token,
    is_64bit: bool,
) -> Option<String> {
    let method = assembly.method(&native_token).ok()?;
    let rva = method.rva.filter(|&r| r > 0)?;

    let native_bytes = assembly.file().section_bounded(rva as usize).ok()?;

    // Use traversal-based disassembly to find where the code ends.
    // This follows control flow edges (including trampolines, call targets,
    // and backward jumps) to find the extent of all reachable instructions.
    let prefix_len = x86_native_body_size(native_bytes, is_64bit);
    if prefix_len == 0 || prefix_len >= native_bytes.len() {
        return None;
    }

    let string_bytes = native_bytes.get(prefix_len..)?;

    // Detect encoding: if the second byte is 0x00 and first byte is printable ASCII,
    // the data is likely UTF-16LE (e.g., "Hello" = 48 00 65 00 6C 00 ...).
    // This check must come before the ASCII attempt, which would find the 0x00 at
    // position 1 and incorrectly return just the first character.
    let looks_like_utf16 = matches!(string_bytes, [b0, 0, b2, 0, ..] if *b0 != 0 && *b2 != 0);

    if looks_like_utf16 {
        // Try UTF-16LE first (char* constructor)
        if let Some(s) = decode_utf16le(string_bytes) {
            return Some(s);
        }
    }

    // Try UTF-8/ASCII (sbyte* constructor)
    if let Some(null_pos) = string_bytes.iter().position(|&b| b == 0) {
        if null_pos > 0 {
            if let Some(slice) = string_bytes.get(..null_pos) {
                if let Ok(s) = std::str::from_utf8(slice) {
                    return Some(s.to_string());
                }
            }
        }
    }

    // Fall back to UTF-16LE if ASCII failed
    if !looks_like_utf16 {
        if let Some(s) = decode_utf16le(string_bytes) {
            return Some(s);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use crate::{
        analysis::x86_native_body_size, deobfuscation::techniques::Technique,
        testkit::helpers::load_sample,
    };

    #[test]
    fn test_x86_body_size_x64_pattern() {
        // x64: lea rax, [rip+1]; ret; "Hello"
        let bytes: Vec<u8> = vec![
            0x48, 0x8D, 0x05, 0x01, 0x00, 0x00, 0x00, // lea rax, [rip+1]
            0xC3, // ret
            b'H', b'e', b'l', b'l', b'o', 0x00,
        ];
        let body_size = x86_native_body_size(&bytes, true);
        assert_eq!(body_size, 8, "x64 stub: LEA + RET = 8 bytes");

        let string_bytes = &bytes[body_size..];
        let null_pos = string_bytes.iter().position(|&b| b == 0).unwrap();
        let extracted = std::str::from_utf8(&string_bytes[..null_pos]).unwrap();
        assert_eq!(extracted, "Hello");
    }

    #[test]
    fn test_x86_body_size_simple_pattern() {
        // Simplified x86: push ebp; mov ebp,esp; lea eax,[ebp+8]; pop ebp; ret
        let bytes: Vec<u8> = vec![
            0x55, // push ebp
            0x89, 0xE5, // mov ebp, esp
            0x8D, 0x45, 0x08, // lea eax, [ebp+8]
            0x5D, // pop ebp
            0xC3, // ret
            b'T', b'e', b's', b't', 0x00,
        ];
        let body_size = x86_native_body_size(&bytes, false);
        assert_eq!(body_size, 8);
    }

    #[test]
    fn test_x86_body_size_trampoline_pattern() {
        // BitMono's actual x86 trampoline:
        // push ebp; mov ebp,esp; call $+5; add eax,1; pop ebp; ret;
        // pop eax; add eax,0x0b; jmp -8; <string data>
        let bytes: Vec<u8> = vec![
            0x55, // push ebp
            0x89, 0xE5, // mov ebp, esp
            0xE8, 0x05, 0x00, 0x00, 0x00, // call $+5
            0x83, 0xC0, 0x01, // add eax, 1
            0x5D, // pop ebp
            0xC3, // ret (offset 12)
            0x58, // pop eax (trampoline start -- call target)
            0x83, 0xC0, 0x0B, // add eax, 0x0b
            0xEB, 0xF8, // jmp -8 (back to ret)
            // String data starts at offset 19
            b'H', b'e', b'l', b'l', b'o', 0x00,
        ];
        let body_size = x86_native_body_size(&bytes, false);
        assert_eq!(
            body_size, 19,
            "Traversal should follow call target through the trampoline"
        );

        let string_bytes = &bytes[body_size..];
        let null_pos = string_bytes.iter().position(|&b| b == 0).unwrap();
        let extracted = std::str::from_utf8(&string_bytes[..null_pos]).unwrap();
        assert_eq!(extracted, "Hello");
    }

    #[test]
    fn test_x86_body_size_empty() {
        let bytes = vec![];
        assert_eq!(x86_native_body_size(&bytes, false), 0);
    }

    #[test]
    fn test_detect_positive() {
        let assembly = load_sample("packers/bitmono/0.39.0/bitmono_unmanagedstring.exe");

        let technique = super::BitMonoUnmanaged;
        let detection = technique.detect(&assembly);

        assert!(
            detection.is_detected(),
            "BitMonoUnmanaged should detect fake native methods in bitmono_unmanagedstring.exe"
        );
        assert!(
            !detection.evidence().is_empty(),
            "Detection should include evidence"
        );
    }

    #[test]
    fn test_detect_negative() {
        let assembly = load_sample("packers/confuserex/1.6.0/original.exe");

        let technique = super::BitMonoUnmanaged;
        let detection = technique.detect(&assembly);

        assert!(
            !detection.is_detected(),
            "BitMonoUnmanaged should not detect fake native methods in a non-BitMono assembly"
        );
    }
}

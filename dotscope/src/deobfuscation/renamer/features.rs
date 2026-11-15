//! SSA-based feature extraction for rename context building.
//!
//! Extracts structural and semantic features from SSA functions and metadata
//! to populate [`RenameContext`] for name inference. Features include:
//!
//! - **Call targets**: Fully-qualified external method names (strongest signal)
//! - **String literals**: Embedded string constants
//! - **Field accesses**: Fields loaded/stored within a method
//! - **Opcode profile**: Semantic classification of operations
//! - **Anchors**: Known parameter names from external API calls

use std::collections::HashSet;

#[cfg(any(feature = "smart-rename", test))]
use crate::deobfuscation::renamer::context::ApiCallInfo;
use crate::{
    analysis::{ConstValue, SsaFunction, SsaOp, SsaOpCilExt},
    deobfuscation::{renamer::context::OpcodeProfile, utils::is_obfuscated_name},
    metadata::token::Token,
    CilObject,
};

/// Collects fully-qualified call targets from a method's SSA representation.
///
/// Walks all calls naming their method, resolves the method token
/// to a human-readable name, and builds a "DeclaringType::MethodName" string
/// for external methods. Deduplicates by name.
///
/// # Arguments
///
/// * `ssa` - The SSA function to analyze.
/// * `assembly` - The assembly for metadata resolution.
///
/// # Returns
///
/// A deduplicated list of fully-qualified call target strings.
pub fn collect_call_targets(ssa: &SsaFunction, assembly: &CilObject) -> Vec<String> {
    let mut targets = Vec::new();
    let mut seen = HashSet::new();

    for (_block_idx, _instr_idx, instr) in ssa.iter_instructions() {
        let method_token = match instr.op() {
            SsaOp::NewObj { ctor, .. } => ctor.token(),
            op => match op.method_call() {
                Some((token, _)) => token,
                None => continue,
            },
        };

        if let Some(name) = resolve_qualified_method_name(assembly, method_token) {
            // Skip calls to obfuscated internal methods — they add noise, not signal.
            // Only keep calls where the method name part is readable.
            if has_obfuscated_component(&name) {
                continue;
            }
            if seen.insert(name.clone()) {
                targets.push(name);
            }
        }
    }

    targets
}

/// Collects string literals from a method's SSA representation.
///
/// Walks all `Const` instructions looking for `DecryptedString` values
/// (produced by the string decryption pass) and `String` values (ldstr
/// heap references, resolved via the UserStrings heap).
///
/// # Returns
///
/// A list of string literal values found in the method body.
pub fn collect_string_literals(ssa: &SsaFunction, assembly: &CilObject) -> Vec<String> {
    let mut strings = Vec::new();

    for (_block_idx, _instr_idx, instr) in ssa.iter_instructions() {
        if let SsaOp::Const { value, .. } = instr.op() {
            match value {
                ConstValue::DecryptedString(s) if !s.is_empty() => {
                    strings.push(s.to_string());
                }
                ConstValue::String(idx) => {
                    // Resolve from UserStrings heap
                    if let Some(us) = assembly.userstrings() {
                        if let Ok(s) = us.get(*idx as usize) {
                            if !s.is_empty() {
                                if let Ok(decoded) = s.to_string() {
                                    strings.push(decoded);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    strings
}

/// Collects field access descriptions from a method's SSA representation.
///
/// Walks `LoadField`, `StoreField`, `LoadStaticField`, and `StoreStaticField`
/// instructions, resolves the field token, and produces a "Type.fieldName" string.
///
/// # Returns
///
/// A deduplicated list of field access descriptions.
pub fn collect_field_accesses(ssa: &SsaFunction, assembly: &CilObject) -> Vec<String> {
    let mut accesses = Vec::new();
    let mut seen = HashSet::new();

    for (_block_idx, _instr_idx, instr) in ssa.iter_instructions() {
        let field_token = match instr.op() {
            SsaOp::LoadField { field, .. }
            | SsaOp::StoreField { field, .. }
            | SsaOp::LoadStaticField { field, .. }
            | SsaOp::StoreStaticField { field, .. }
            | SsaOp::LoadFieldAddr { field, .. }
            | SsaOp::LoadStaticFieldAddr { field, .. } => field.token(),
            _ => continue,
        };

        if let Some(name) = resolve_qualified_field_name(assembly, field_token) {
            if has_obfuscated_component(&name) {
                continue;
            }
            if seen.insert(name.clone()) {
                accesses.push(name);
            }
        }
    }

    accesses
}

/// Builds a semantic opcode profile for a method's SSA representation.
///
/// Classifies each SSA operation into one of several semantic categories
/// (calls, strings, field I/O, bitwise, arithmetic, array, comparison,
/// conversion) to characterize the method's behavior pattern.
pub fn build_opcode_profile(ssa: &SsaFunction) -> OpcodeProfile {
    let mut profile = OpcodeProfile::default();

    for (_block_idx, _instr_idx, instr) in ssa.iter_instructions() {
        match instr.op() {
            // Calls
            SsaOp::Call(_) => {
                profile.calls = profile.calls.saturating_add(1);
            }

            // Strings
            SsaOp::Const {
                value: ConstValue::String(_) | ConstValue::DecryptedString(_),
                ..
            } => {
                profile.strings = profile.strings.saturating_add(1);
            }

            // Field I/O
            SsaOp::LoadField { .. }
            | SsaOp::StoreField { .. }
            | SsaOp::LoadStaticField { .. }
            | SsaOp::StoreStaticField { .. }
            | SsaOp::LoadFieldAddr { .. }
            | SsaOp::LoadStaticFieldAddr { .. } => {
                profile.field_io = profile.field_io.saturating_add(1);
            }

            // Bitwise
            SsaOp::And { .. }
            | SsaOp::Or { .. }
            | SsaOp::Xor { .. }
            | SsaOp::Not { .. }
            | SsaOp::Shl { .. }
            | SsaOp::Shr { .. } => {
                profile.bitwise = profile.bitwise.saturating_add(1);
            }

            // Arithmetic
            SsaOp::Add { .. }
            | SsaOp::AddOvf { .. }
            | SsaOp::Sub { .. }
            | SsaOp::SubOvf { .. }
            | SsaOp::Mul { .. }
            | SsaOp::MulOvf { .. }
            | SsaOp::Div { .. }
            | SsaOp::Rem { .. }
            | SsaOp::Neg { .. } => {
                profile.arithmetic = profile.arithmetic.saturating_add(1);
            }

            // Array
            SsaOp::NewArr { .. }
            | SsaOp::LoadElement { .. }
            | SsaOp::StoreElement { .. }
            | SsaOp::LoadElementAddr { .. }
            | SsaOp::ArrayLength { .. } => {
                profile.array = profile.array.saturating_add(1);
            }

            // Comparison
            SsaOp::Ceq { .. }
            | SsaOp::Clt { .. }
            | SsaOp::Cgt { .. }
            | SsaOp::Branch { .. }
            | SsaOp::BranchCmp { .. } => {
                profile.comparison = profile.comparison.saturating_add(1);
            }

            // Conversion
            SsaOp::IntConv { .. }
            | SsaOp::IntToPtr { .. }
            | SsaOp::PtrToInt { .. }
            | SsaOp::IntToFloat { .. }
            | SsaOp::FloatToInt { .. }
            | SsaOp::FloatConv { .. } => {
                profile.conversion = profile.conversion.saturating_add(1);
            }

            _ => {}
        }
    }

    profile
}

/// Extracts anchor information from known API calls in a method.
///
/// For each call of an external method (resolved via MemberRef),
/// maps each argument position to the call target. This provides the anchor
/// system: if we know that argument 0 of `File.WriteAllText` is called "path",
/// any SSA variable passed in that position can be named accordingly.
///
/// # Returns
///
/// A list of [`ApiCallInfo`] entries, one per argument of each resolved call.
#[cfg(any(feature = "smart-rename", test))]
pub fn extract_anchors(ssa: &SsaFunction, assembly: &CilObject) -> Vec<ApiCallInfo> {
    let mut anchors = Vec::new();

    for (_block_idx, _instr_idx, instr) in ssa.iter_instructions() {
        let Some((method_token, call)) = instr.op().method_call() else {
            continue;
        };
        let args = &call.args;

        let Some(method_name) = resolve_qualified_method_name(assembly, method_token) else {
            continue;
        };

        // Only anchor from external calls (MemberRef-based)
        if method_token.table() != 0x0A && method_token.table() != 0x2B {
            continue;
        }

        for (pos, _arg) in args.iter().enumerate() {
            anchors.push(ApiCallInfo {
                method_name: method_name.clone(),
                argument_position: Some(pos),
            });
        }
    }

    anchors
}

/// Extracts caller-side context for a specific call site.
///
/// Scans the caller's SSA for calls of `callee_token`,
/// then collects:
/// - String literals within a ±3 instruction window around the call site
/// - The method name that the call's return value is passed to (if any)
///
/// # Arguments
///
/// * `caller_ssa` - The SSA of the calling method.
/// * `callee_token` - The token of the method being called.
/// * `assembly` - The assembly for metadata resolution.
///
/// # Returns
///
/// A tuple of `(nearby_strings, return_usage)`.
#[cfg(any(feature = "smart-rename", test))]
pub fn collect_call_site_context(
    caller_ssa: &SsaFunction,
    callee_token: Token,
    assembly: &CilObject,
) -> (Vec<String>, Option<String>) {
    let mut nearby_strings = Vec::new();
    let mut return_usage: Option<String> = None;

    // Collect all instructions into a flat list for window-based scanning
    let all_instrs: Vec<_> = caller_ssa.iter_instructions().collect();

    for (idx, (_block_idx, _instr_idx, instr)) in all_instrs.iter().enumerate() {
        // Find calls of the callee
        let Some((method_token, call)) = instr.op().method_call() else {
            continue;
        };
        let dest = &call.dest;

        // SSA calls may use MemberRef tokens while callee_token is a MethodDef.
        // Resolve to MethodDef for comparison.
        let resolved = assembly
            .resolver()
            .resolve_method(method_token)
            .unwrap_or(method_token);
        if resolved != callee_token && method_token != callee_token {
            continue;
        }

        // Collect string literals within ±5 instructions.
        // In SSA form, ldstr constants can be several instructions away from
        // the call site (e.g., format strings loaded before String.Format which
        // comes after the method call whose result is being formatted).
        let window_start = idx.saturating_sub(5);
        let window_end = idx.saturating_add(6).min(all_instrs.len());
        let Some(window) = all_instrs.get(window_start..window_end) else {
            continue;
        };
        for (_, _, nearby_instr) in window {
            if let SsaOp::Const { value, .. } = nearby_instr.op() {
                match value {
                    ConstValue::DecryptedString(s) if !s.is_empty() => {
                        let s = s.to_string();
                        if !nearby_strings.contains(&s) {
                            nearby_strings.push(s);
                        }
                    }
                    ConstValue::String(us_idx) => {
                        if let Some(us) = assembly.userstrings() {
                            if let Ok(s) = us.get(*us_idx as usize) {
                                if !s.is_empty() {
                                    if let Ok(decoded) = s.to_string() {
                                        if !nearby_strings.contains(&decoded) {
                                            nearby_strings.push(decoded);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Check if the return value feeds into another call
        if let Some(dest_var) = dest {
            for (_, _, later_instr) in all_instrs.iter().skip(idx.saturating_add(1)).take(5) {
                let Some((usage_token, usage)) = later_instr.op().method_call() else {
                    continue;
                };
                if usage.args.contains(dest_var) {
                    if let Some(name) = resolve_qualified_method_name(assembly, usage_token) {
                        if !has_obfuscated_component(&name) {
                            return_usage = Some(name);
                        }
                    }
                    break;
                }
            }
        }

        // One call site is enough for context
        break;
    }

    // Cap nearby strings to avoid noise
    nearby_strings.truncate(3);

    (nearby_strings, return_usage)
}

/// Resolves a method token to a "Namespace.Type::MethodName" string.
///
/// For MemberRef tokens, uses `member_ref()` to get `declaredby.fullname()` and name.
/// For MethodDef tokens, uses the method's declaring type.
fn resolve_qualified_method_name(assembly: &CilObject, token: Token) -> Option<String> {
    match token.table() {
        // MemberRef
        0x0A => {
            let member = assembly.member_ref(&token)?;
            let type_name = member.declaredby.fullname()?;
            Some(format!("{type_name}::{}", member.name))
        }
        // MethodDef
        0x06 => {
            let method = assembly.method(&token).ok()?;
            if let Some(type_name) = method.declaring_type_fullname() {
                Some(format!("{type_name}::{}", method.name))
            } else {
                Some(method.name.clone())
            }
        }
        // MethodSpec — resolve to underlying method
        0x2B => {
            let method_name = assembly.resolve_method_name(token)?;
            // resolve_method_name returns just the name, try to get the full qualifier
            let resolver = assembly.resolver();
            if let Some(cil_type) = resolver.declaring_type(token) {
                Some(format!("{}::{method_name}", cil_type.fullname()))
            } else {
                Some(method_name)
            }
        }
        _ => None,
    }
}

/// Resolves a field token to a "Type.fieldName" string.
fn resolve_qualified_field_name(assembly: &CilObject, token: Token) -> Option<String> {
    match token.table() {
        // MemberRef (field reference)
        0x0A => {
            let member = assembly.member_ref(&token)?;
            let type_name = member.declaredby.fullname()?;
            Some(format!("{type_name}.{}", member.name))
        }
        // Field (local field definition)
        0x04 => {
            let resolver = assembly.resolver();
            if let Some(cil_type) = resolver.declaring_type_of_field(token) {
                for (_, field_rc) in cil_type.fields.iter() {
                    if field_rc.token == token {
                        return Some(format!("{}.{}", cil_type.fullname(), field_rc.name));
                    }
                }
            }
            None
        }
        _ => None,
    }
}

/// Checks if any component of a qualified name (e.g., `Namespace.Type::Method`)
/// appears to be obfuscated. Splits on `::`, `.`, and `/` separators and checks
/// each part with [`is_obfuscated_name`].
fn has_obfuscated_component(qualified_name: &str) -> bool {
    qualified_name
        .split([':', '.', '/'])
        .filter(|s| !s.is_empty())
        .any(is_obfuscated_name)
}

#[cfg(test)]
mod tests {
    use crate::deobfuscation::renamer::context::OpcodeProfile;

    #[test]
    fn test_opcode_profile_default() {
        let profile = OpcodeProfile::default();
        assert_eq!(profile.calls, 0);
        assert_eq!(profile.strings, 0);
        assert_eq!(profile.bitwise, 0);
        assert_eq!(profile.arithmetic, 0);
        assert_eq!(profile.array, 0);
        assert_eq!(profile.comparison, 0);
        assert_eq!(profile.conversion, 0);
        assert_eq!(profile.field_io, 0);
    }
}

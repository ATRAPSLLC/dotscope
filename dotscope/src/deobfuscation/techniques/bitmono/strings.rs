//! BitMono string encryption detection and decryption technique.
//!
//! Detects BitMono's StringsEncryption protection, which encrypts string literals
//! using AES-256-CBC (via `RijndaelManaged` or `Aes`) with PBKDF2-HMAC-SHA1 key
//! derivation (`Rfc2898DeriveBytes`). Unlike ConfuserEx (which uses emulation),
//! BitMono's encryption is fully static — the key material is embedded as FieldRVA
//! data and the algorithm is standard AES-256-CBC.
//!
//! # CIL Pattern
//!
//! Each string literal is replaced with a 4-instruction sequence:
//! ```text
//! ldsfld     byte[] <encrypted_data_field>     // per-string FieldRVA data
//! ldsfld     byte[] <salt_field>               // shared 8-byte salt
//! ldsfld     byte[] <crypt_key_field>          // shared 8-byte key
//! call       string Decrypt(byte[], byte[], byte[])
//! ```
//!
//! # Detection
//!
//! Scans all static methods for references to crypto types:
//! - `RijndaelManaged` or `Aes` (symmetric cipher)
//! - `Rfc2898DeriveBytes` (key derivation)
//!
//! Also checks for the characteristic decryptor signature: a static method
//! returning `string` that takes 3+ `byte[]` parameters.
//!
//! # Feature Gate
//!
//! The actual string decryption requires the `legacy-crypto` feature for
//! PBKDF2-HMAC-SHA1 key derivation. Detection works without the feature,
//! but decryption is only available when `legacy-crypto` is enabled.
//!
//! # Two-Phase Design
//!
//! **Phase A — `initialize()`** (byte-level, runs before SSA):
//! - Tags infrastructure fields in the analysis context (encrypted data, salt, key fields)
//! - Registers decryptor method tokens so cleanup knows what to remove
//!
//! **Phase B — `StringDecryptionPass`** (SSA pass, runs AFTER `ReflectionDevirtualizationPass`):
//! - Finds `Call` to decryptor methods in SSA blocks
//! - Traces each site's `LoadStaticField` args to identify its specific encrypted
//!   data, salt, and key fields
//! - Derives AES key material per (salt, key) pair (cached for efficiency)
//! - Decrypts only fields actually referenced as decryptor arguments
//! - Replaces `Call` with `DecryptedString` constant, NOPs intermediate instructions

use std::{
    any::Any,
    collections::{HashMap, HashSet},
    sync::Arc,
};

#[cfg(feature = "legacy-crypto")]
use crate::deobfuscation::passes::bitmono::StringDecryptionPass;
use crate::{
    analysis::{CilTarget, ConstValue, SsaFunction, SsaOp, SsaVarId},
    cilassembly::CleanupRequest,
    compiler::{CompilerContext, PassPhase, SsaPass},
    deobfuscation::{
        config::EngineConfig,
        context::AnalysisContext,
        techniques::{Detection, Evidence, Technique, TechniqueCategory},
        utils::build_init_array_map,
    },
    metadata::{
        tables::{MemberRefRaw, MetadataTable, RowReadable, TableId, TypeDefRaw, TypeRefRaw},
        token::Token,
    },
    utils::CryptoParameters,
    CilObject,
};

/// Findings from BitMono string encryption detection.
#[derive(Debug)]
pub struct StringFindings {
    /// Token of the type containing the decryptor method, if identified.
    pub decryptor_type: Option<Token>,
    /// Tokens of identified decryptor methods.
    pub decryptor_tokens: Vec<Token>,
    /// Number of call sites that invoke the decryptor method.
    pub call_sites: usize,
    /// Infrastructure field tokens (encrypted data fields, salt, key).
    /// These are `byte[]` static fields loaded by decryptor call sites.
    pub infrastructure_fields: Vec<Token>,
    /// FieldRVA backing field tokens (ExplicitLayout structs initialized via
    /// `RuntimeHelpers.InitializeArray` to hold raw encrypted data).
    pub constant_data_fields: Vec<Token>,
    /// Types owning the FieldRVA backing fields (ExplicitLayout value types).
    pub constant_data_types: Vec<Token>,
    /// Crypto parameters extracted from the decryptor method's SSA.
    pub crypto_params: CryptoParameters,
}

/// Detects BitMono's AES+PBKDF2 string encryption.
///
/// Identifies the decryptor infrastructure by scanning for methods that
/// reference `RijndaelManaged`/`Aes` and `Rfc2898DeriveBytes`, or by
/// matching the characteristic `string(byte[], byte[], byte[])` signature.
/// Requires the `bitmono.calli` technique to run first so that `calli`
/// trampolines have been resolved to direct calls before decryption.
pub struct BitMonoStrings;

impl Technique for BitMonoStrings {
    fn id(&self) -> &'static str {
        "bitmono.strings"
    }

    fn name(&self) -> &'static str {
        "BitMono String Decryption"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Value
    }

    fn requires(&self) -> &[&'static str] {
        &["bitmono.calli"]
    }

    #[cfg(feature = "legacy-crypto")]
    fn enabled(&self, _config: &EngineConfig) -> bool {
        true
    }

    #[cfg(not(feature = "legacy-crypto"))]
    fn enabled(&self, _config: &EngineConfig) -> bool {
        false
    }

    fn detect(&self, _assembly: &CilObject) -> Detection {
        // IL-level detection is not used — all detection happens in detect_ssa()
        // where SSA def-use chains give us precise crypto parameter extraction
        // and junk-immune decryptor identification.
        Detection::new_empty()
    }

    fn detect_ssa(&self, ctx: &AnalysisContext, assembly: &CilObject) -> Detection {
        // Phase 1: Find decryptor methods by scanning SSA for NewObj targeting
        // crypto types (Rfc2898DeriveBytes, RijndaelManaged/Aes).
        let mut decryptor_tokens: Vec<Token> = Vec::new();
        let mut decryptor_type: Option<Token> = None;

        for entry in ctx.ssa_functions.iter() {
            let method_token = *entry.key();
            let ssa = entry.value();

            if has_crypto_ops(ssa, assembly) {
                decryptor_tokens.push(method_token);
                if decryptor_type.is_none() {
                    if let Ok(method) = assembly.method(&method_token) {
                        if let Some(decl_type) = method.declaring_type_rc() {
                            decryptor_type = Some(decl_type.token);
                        }
                    }
                }
            }
        }

        if decryptor_tokens.is_empty() {
            return Detection::new_empty();
        }

        // Phase 2: Extract crypto parameters from the first decryptor's SSA.
        let crypto_params = decryptor_tokens
            .first()
            .and_then(|token| ctx.ssa_functions.get(token))
            .map(|ssa| extract_crypto_parameters(&ssa, assembly))
            .unwrap_or_default();

        log::info!(
            "BitMono strings: extracted crypto params — {} iterations, {}/{} key/iv, {}",
            crypto_params.iterations,
            crypto_params.key_size,
            crypto_params.iv_size,
            crypto_params.hash_algorithm,
        );

        // Phase 3: Count call sites and collect infrastructure fields via SSA.
        let decryptor_set: HashSet<Token> = decryptor_tokens.iter().copied().collect();
        let mut call_site_count = 0usize;
        let mut infrastructure_fields: Vec<Token> = Vec::new();

        for entry in ctx.ssa_functions.iter() {
            let ssa = entry.value();
            for block in ssa.blocks() {
                for instr in block.instructions() {
                    let (call_token, args) = match instr.op() {
                        SsaOp::Call { method, args, .. } => (method.token(), args),
                        _ => continue,
                    };
                    if !decryptor_set.contains(&call_token) {
                        continue;
                    }
                    call_site_count = call_site_count.saturating_add(1);

                    // Trace LoadStaticField args to collect infrastructure field tokens
                    for arg in args {
                        if let Some(field_token) = resolve_ldsfld_field(ssa, *arg) {
                            if !infrastructure_fields.contains(&field_token) {
                                infrastructure_fields.push(field_token);
                            }
                        }
                    }
                }
            }
        }

        // Phase 4: Collect FieldRVA backing fields and their owning types.
        let (constant_data_fields, constant_data_types) =
            collect_constant_data_tokens(assembly, &infrastructure_fields);

        let mut evidence = vec![Evidence::BytecodePattern(
            "BitMono string decryptor (AES + Rfc2898DeriveBytes)".to_string(),
        )];

        if call_site_count > 0 {
            evidence.push(Evidence::BytecodePattern(format!(
                "{call_site_count} call sites reference the string decryptor"
            )));
        }

        let findings = StringFindings {
            decryptor_type,
            decryptor_tokens,
            call_sites: call_site_count,
            infrastructure_fields,
            constant_data_fields,
            constant_data_types,
            crypto_params,
        };

        Detection::new_detected(
            evidence,
            Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
        )
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        Some(PassPhase::Simplify)
    }

    #[cfg(feature = "legacy-crypto")]
    fn create_pass(
        &self,
        ctx: &AnalysisContext,
        detection: &Detection,
        _assembly: &Arc<CilObject>,
    ) -> Vec<Box<dyn SsaPass<CilTarget, CompilerContext>>> {
        let Some(findings) = detection.findings::<StringFindings>() else {
            return Vec::new();
        };
        // The key derivation is held to what emulating the decryptor's own call could spend
        vec![Box::new(StringDecryptionPass::from_findings(
            findings,
            findings.crypto_params.clone(),
            ctx.emulation_max_instructions(),
        ))]
    }

    #[cfg(not(feature = "legacy-crypto"))]
    fn create_pass(
        &self,
        _ctx: &AnalysisContext,
        _detection: &Detection,
        _assembly: &Arc<CilObject>,
    ) -> Vec<Box<dyn SsaPass<CilTarget, CompilerContext>>> {
        Vec::new()
    }

    fn cleanup(&self, detection: &Detection) -> Option<CleanupRequest> {
        let findings = detection.findings::<StringFindings>()?;

        let mut request = CleanupRequest::new();

        // Remove the decryptor type (cascades to its methods and fields)
        if let Some(decryptor_type) = findings.decryptor_type {
            request.add_type(decryptor_type);
        }

        // Remove infrastructure fields (encrypted data byte[] fields, salt, key)
        for token in &findings.infrastructure_fields {
            request.add_field(*token);
        }

        // Remove FieldRVA backing fields (ExplicitLayout data holders)
        for token in &findings.constant_data_fields {
            request.add_field(*token);
        }

        // Remove ExplicitLayout value types that own the backing fields.
        // These extend System.ValueType, so removing them cascades to remove
        // the ValueType TypeRef → System.Private.CoreLib AssemblyRef chain.
        for token in &findings.constant_data_types {
            request.add_type(*token);
        }

        if request.has_deletions() {
            Some(request)
        } else {
            None
        }
    }
}

/// Collects FieldRVA backing field tokens and their owning ExplicitLayout types.
///
/// Scans `.cctor` methods for `RuntimeHelpers.InitializeArray` patterns to build
/// a mapping from byte[] field → backing FieldRVA field. For each infrastructure
/// field that has a backing field, the backing field token is collected. The owning
/// ExplicitLayout value types are also collected — removing these cascades to remove
/// the `ValueType` TypeRef → `System.Private.CoreLib` AssemblyRef chain.
fn collect_constant_data_tokens(
    assembly: &CilObject,
    infrastructure_fields: &[Token],
) -> (Vec<Token>, Vec<Token>) {
    let mut constant_data_fields = Vec::new();
    let mut constant_data_types = Vec::new();

    if infrastructure_fields.is_empty() {
        return (constant_data_fields, constant_data_types);
    }

    // Build mapping: byte_array_field_token → backing_field_token
    let init_map = build_init_array_map(assembly);
    if init_map.is_empty() {
        return (constant_data_fields, constant_data_types);
    }

    // Collect backing field tokens for infrastructure fields
    for infra_token in infrastructure_fields {
        if let Some(&backing_token) = init_map.get(infra_token) {
            if !constant_data_fields.contains(&backing_token) {
                constant_data_fields.push(backing_token);
            }
        }
    }

    // Find types that ONLY contain infrastructure backing fields — safe to remove.
    // A type like `<PrivateImplementationDetails>` may contain both string encryption
    // backing fields (removable) AND RuntimeHelpers.InitializeArray backing fields
    // (must survive). Only mark the type for deletion if ALL its FieldRVA fields
    // are being removed — otherwise we'd break array initialization.
    let removed_set: HashSet<Token> = constant_data_fields.iter().copied().collect();

    for type_entry in assembly.types().iter() {
        let cil_type = type_entry.value();

        if cil_type.token.row() == 1 && cil_type.token.table() == 0x02 {
            continue;
        }

        // Collect all FieldRVA-backed fields owned by this type
        let rva_fields: Vec<Token> = cil_type
            .fields
            .iter()
            .filter(|(_, field)| field.flags.has_field_rva())
            .map(|(_, field)| field.token)
            .collect();

        if rva_fields.is_empty() {
            continue;
        }

        // Only remove the type if ALL its FieldRVA fields are being removed.
        // If some survive (e.g., InitializeArray backing data), the type must too.
        if rva_fields.iter().all(|t| removed_set.contains(t)) {
            constant_data_types.push(cil_type.token);
        }
    }

    (constant_data_fields, constant_data_types)
}

/// Checks whether an SSA function contains NewObj/Call targeting crypto types.
///
/// Scans for `NewObj` or `Call` instructions whose resolved target name contains
/// both an AES type (`RijndaelManaged` or `Aes`) and `Rfc2898DeriveBytes`.
///
/// # Arguments
///
/// * `ssa` - The SSA function to scan.
/// * `assembly` - The assembly for resolving type names from metadata tokens.
fn has_crypto_ops(ssa: &SsaFunction, assembly: &CilObject) -> bool {
    let mut has_aes = false;
    let mut has_pbkdf2 = false;

    for block in ssa.blocks() {
        for instr in block.instructions() {
            let token = match instr.op() {
                SsaOp::NewObj { ctor, .. } => ctor.token(),
                SsaOp::Call { method, .. } | SsaOp::CallVirt { method, .. } => method.token(),
                _ => continue,
            };

            if let Some(name) = resolve_type_name(assembly, token) {
                if name.contains("RijndaelManaged") || name.contains("Aes") {
                    has_aes = true;
                }
                if name.contains("Rfc2898DeriveBytes") {
                    has_pbkdf2 = true;
                }
            }

            if has_aes && has_pbkdf2 {
                return true;
            }
        }
    }

    false
}

/// Extracts crypto parameters from a decryptor method's SSA.
///
/// Scans the SSA for:
/// 1. `NewObj { ctor: Rfc2898DeriveBytes::.ctor, args: [..., iterations] }` to get
///    the PBKDF2 iteration count
/// 2. `CallVirt { method: GetBytes, args: [_, size] }` to get key and IV sizes
///
/// Falls back to [`CryptoParameters::default()`] for any parameter that cannot
/// be resolved from the SSA.
fn extract_crypto_parameters(ssa: &SsaFunction, assembly: &CilObject) -> CryptoParameters {
    let mut params = CryptoParameters::default();

    // Build a map from SsaVarId → ConstValue for resolving arguments
    let const_map = build_const_map(ssa);

    let mut get_bytes_sizes: Vec<u32> = Vec::new();

    for block in ssa.blocks() {
        for instr in block.instructions() {
            match instr.op() {
                // NewObj Rfc2898DeriveBytes(key, salt, iterations)
                // or NewObj Rfc2898DeriveBytes(key, salt, iterations, hashAlgorithm)
                SsaOp::NewObj { ctor, args, .. } => {
                    if let Some(name) = resolve_type_name(assembly, ctor.token()) {
                        if name.contains("Rfc2898DeriveBytes") && args.len() >= 3 {
                            // 3rd arg (index 2) is the iteration count
                            if let Some(ConstValue::I32(iters)) =
                                args.get(2).and_then(|a| const_map.get(a))
                            {
                                if *iters > 0 {
                                    params.iterations = *iters as u32;
                                }
                            }
                            // 4th arg (index 3), if present, is HashAlgorithmName
                            // For now we keep SHA1 default — .NET's HashAlgorithmName
                            // is a struct loaded via ldsfld, not a simple constant.
                        }
                    }
                }
                // CallVirt GetBytes(int32) — extract key and IV sizes
                SsaOp::CallVirt { method, args, .. } => {
                    if let Some(name) = assembly.resolve_method_name(method.token()) {
                        if name == "GetBytes" && args.len() == 2 {
                            // args[0] = this (Rfc2898DeriveBytes instance), args[1] = size
                            if let Some(ConstValue::I32(size)) =
                                args.get(1).and_then(|a| const_map.get(a))
                            {
                                if *size > 0 {
                                    get_bytes_sizes.push(*size as u32);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // First GetBytes call = key size, second = IV size
    if let Some(&key_size) = get_bytes_sizes.first() {
        params.key_size = key_size as usize;
    }
    if let Some(&iv_size) = get_bytes_sizes.get(1) {
        params.iv_size = iv_size as usize;
    }

    params
}

/// Builds a map from SSA variable IDs to their constant values.
///
/// Only includes variables defined by `Const` instructions. Used for resolving
/// arguments to crypto API calls during parameter extraction.
///
/// # Arguments
///
/// * `ssa` - The SSA function to scan for constant definitions.
fn build_const_map(ssa: &SsaFunction) -> HashMap<SsaVarId, ConstValue> {
    let mut map = HashMap::new();
    for block in ssa.blocks() {
        for instr in block.instructions() {
            if let SsaOp::Const { dest, value } = instr.op() {
                map.insert(*dest, value.clone());
            }
        }
    }
    map
}

/// Resolves a `LoadStaticField` definition for an SSA variable.
///
/// Scans the SSA for the instruction that defines `var_id` and returns the
/// field token if it's a `LoadStaticField`.
///
/// # Arguments
///
/// * `ssa` - The SSA function containing the variable definition.
/// * `var_id` - The SSA variable ID to resolve.
fn resolve_ldsfld_field(ssa: &SsaFunction, var_id: SsaVarId) -> Option<Token> {
    for block in ssa.blocks() {
        for instr in block.instructions() {
            if let SsaOp::LoadStaticField { dest, field } = instr.op() {
                if *dest == var_id {
                    return Some(field.token());
                }
            }
        }
    }
    None
}

/// Resolves a metadata token to a type name string for crypto detection.
///
/// For MemberRef tokens, follows the class reference to get the declaring type name.
/// For TypeRef tokens, returns the type name directly. For TypeDef tokens, returns
/// the type name from the local assembly.
fn resolve_type_name(assembly: &CilObject, token: Token) -> Option<String> {
    let tables = assembly.tables()?;
    let strings = assembly.strings()?;

    /// Reads one row, treating both "no such row" and "row does not parse" as "no name".
    ///
    /// This function has no error channel — it answers `Option<String>` — so an unreadable
    /// row cannot be propagated. `.ok().flatten()` is that decision written down: the row is
    /// given up on here, at the point that can see it, rather than inside the iterator.
    fn row<T: RowReadable>(table: &MetadataTable<'_, T>, rid: u32) -> Option<T> {
        table.get(rid).ok().flatten()
    }

    let type_name = |namespace_idx: u32, name_idx: u32| -> Option<String> {
        let name = strings.get(name_idx as usize).ok()?;
        let ns = strings.get(namespace_idx as usize).unwrap_or("");
        Some(format!("{ns}.{name}"))
    };

    match token.table() {
        // MemberRef (0x0A) — follow class to get declaring type
        0x0A => {
            let memberref = row(tables.table::<MemberRefRaw>()?, token.row())?;
            if memberref.class.tag == TableId::TypeRef {
                let typeref = row(tables.table::<TypeRefRaw>()?, memberref.class.row)?;
                type_name(typeref.type_namespace, typeref.type_name)
            } else if memberref.class.tag == TableId::TypeDef {
                let typedef = row(tables.table::<TypeDefRaw>()?, memberref.class.row)?;
                type_name(typedef.type_namespace, typedef.type_name)
            } else {
                None
            }
        }
        // TypeRef (0x01)
        0x01 => {
            let typeref = row(tables.table::<TypeRefRaw>()?, token.row())?;
            type_name(typeref.type_namespace, typeref.type_name)
        }
        // TypeDef (0x02)
        0x02 => {
            let typedef = row(tables.table::<TypeDefRaw>()?, token.row())?;
            type_name(typedef.type_namespace, typedef.type_name)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::techniques::{bitmono::BitMonoStrings, Technique},
        testkit::helpers::load_sample,
    };

    /// Verify that IL-level detect() is a no-op (detection is SSA-based).
    ///
    /// Positive detection is tested through the full pipeline in
    /// `full::bitmono::test_all_bitmono_samples` (`dotscope/tests/it/full/bitmono.rs`).
    #[test]
    fn test_detect_is_noop() {
        let assembly = load_sample("packers/bitmono/0.39.0/bitmono_strings.exe");
        let technique = BitMonoStrings;
        let detection = technique.detect(&assembly);
        assert!(
            !detection.is_detected(),
            "IL-level detect() should be a no-op — detection happens in detect_ssa()"
        );
    }

    #[test]
    fn test_detect_negative() {
        let assembly = load_sample("packers/confuserex/1.6.0/original.exe");
        let technique = BitMonoStrings;
        let detection = technique.detect(&assembly);
        assert!(
            !detection.is_detected(),
            "BitMonoStrings should not detect string encryption in a non-BitMono assembly"
        );
    }
}

//! ConfuserEx constants protection detection and decryption.
//!
//! ConfuserEx constants protection encrypts strings, numbers, and arrays by
//! replacing literal values with calls to generic decryptor methods of the form
//! `T Get<T>(int32)`. The encrypted data is stored in a FieldRVA-backed field,
//! compressed with LZMA, and decrypted at runtime via an initialization method.
//!
//! # Source Code Analysis
//!
//! Based on analysis of the ConfuserEx source code at:
//! - `Confuser.Protections/Constants/ConstantProtection.cs` — Protection entry point
//! - `Confuser.Protections/Constants/EncodePhase.cs` — Constant encoding
//! - `Confuser.Protections/Constants/ReferenceReplacer.cs` — Call site replacement
//! - `Confuser.Protections/Constants/DynamicMode.cs` — Dynamic cipher mode
//! - `Confuser.Protections/Constants/CEContext.cs` — Context structure
//! - `Confuser.Runtime/Constant.cs` — Runtime decryption & CFGCtx
//!
//! Constants protection is part of the **Normal** preset.
//!
//! # Architecture Overview
//!
//! ## Encoding Phase
//!
//! 1. All string literals and constants are collected from method bodies
//! 2. Constants are encoded into a byte array with type tags:
//!    - Type 0: String (UTF-8 encoded, length-prefixed)
//!    - Type 1: Primitive value (int, long, float, double, etc.)
//!    - Type 2: Array of primitives
//! 3. The byte array is encrypted using XOR with a derived key
//! 4. The encrypted data is compressed with LZMA
//! 5. The compressed data is stored in a FieldRVA (static field with init data)
//!
//! ## Runtime Initialization (`Confuser.Runtime/Constant.cs`)
//!
//! ```text
//! internal static class Constant {
//!     static byte[] b;  // Decrypted buffer
//!     static void Initialize() {
//!         var l = (uint)Mutation.KeyI0;           // Length
//!         uint[] q = Mutation.Placeholder(...);   // Encrypted data
//!         var k = new uint[0x10];                 // Key (16 entries)
//!         // XORShift32 key generation
//!         var n = (uint)Mutation.KeyI1;
//!         for (int i = 0; i < 0x10; i++) {
//!             n ^= n >> 12; n ^= n << 25; n ^= n >> 27;
//!             k[i] = n;
//!         }
//!         // XOR decryption with Mutation.Crypt (DynCipher)
//!         b = Lzma.Decompress(o);
//!     }
//!     static T Get<T>(int id) { /* Type-dispatched retrieval */ }
//! }
//! ```
//!
//! # Call Site Replacement Modes
//!
//! ## Normal Mode (`cfg=false`, default)
//!
//! Simple stateless pattern — each call is independent:
//!
//! ```text
//! Original:    ldstr "Hello"
//! Obfuscated:  ldc.i4 0x12345678
//!              call Decryptor<string>
//! ```
//!
//! Key encoding: `encoded = (id ^ key.Item2) * key.Item1`.
//! Key decoding: `id = (encoded * modInv(key.Item1)) ^ key.Item2`.
//!
//! ## CFG Mode (`cfg=true`)
//!
//! Control-flow-aware stateful pattern — calls are order-dependent:
//!
//! ```text
//! ldloc   stateVar          ; Load CFGCtx state variable
//! ldc.i4  INCREMENT         ; State modification value
//! xor                       ; Compute key = ENCODED ^ state_value
//! call    Decryptor<T>      ; Uses computed key
//! ```
//!
//! ### CFGCtx State Machine (`Confuser.Runtime/Constant.cs`)
//!
//! ```text
//! internal struct CFGCtx {
//!     uint A, B, C, D;  // 4 state slots
//!     public CFGCtx(uint seed) {
//!         A = seed *= 0x21412321;
//!         B = seed *= 0x21412321;
//!         C = seed *= 0x21412321;
//!         D = seed *= 0x21412321;
//!     }
//!     public uint Next(byte f, uint q) {
//!         // Update slot (f & 0x3) with value q:
//!         //   Bit 7 (0x80): Explicit (1) vs Incremental (0)
//!         //   Incremental: slot0 ^= q, slot1 += q, slot2 ^= q, slot3 -= q
//!         // Return slot ((f >> 2) & 0x3)
//!     }
//! }
//! ```
//!
//! Calls **MUST** be processed in execution order — the state machine is
//! path-sensitive and each `Next()` call modifies state.
//!
//! # Cipher Modes (Initialize method)
//!
//! - **Normal**: Static XOR encryption with compile-time keys
//! - **Dynamic**: `Mutation.Crypt()` dynamically-generated cipher (unique per assembly)
//! - **x86**: Native x86 code for key derivation (requires `confuserex.natives` first)
//!
//! # Detection
//!
//! Identifies decryptor methods by scanning for:
//! - Generic methods with signature `T(int32)` called from many sites
//! - Static methods returning `string` or `object` with `int32` parameter
//! - FieldRVA-backed fields with LZMA-compressed data (magic bytes `0x5D`)
//! - CFG mode: `xor` + state variable load before decryptor call sites
//!
//! CFG mode detection scans for the `xor` + `ldloc`/`ldsfld` pattern in the
//! argument chain before decryptor calls, using MethodSpec resolution to match
//! generic instantiations back to base decryptor MethodDefs.
//!
//! # Passes
//!
//! Does not create its own SSA pass — uses the shared `DecryptionPass`
//! singleton added by `create_deob_passes()`. During `initialize()`, registers
//! decryptor methods with the analysis context and sets up the LZMA emulation
//! hook and warmup method.
//!
//! # Supersedes
//!
//! Supersedes both `generic.strings` and `generic.constants` since ConfuserEx
//! uses a unified decryptor for all constant types.
//!
//! # Test Samples
//!
//! | Sample | Mode | CFG | Notes |
//! |--------|------|-----|-------|
//! | `mkaring_normal.exe` | Normal | No | Normal preset |
//! | `mkaring_constants.exe` | Normal | No | Constants-only |
//! | `mkaring_constants_dyncyph.exe` | Dynamic | No | `mode=dynamic` |
//! | `mkaring_constants_cfg.exe` | Dynamic | Yes | `cfg=true`, state machine |
//! | `mkaring_constants_x86.exe` | x86 | No | `mode=x86`, native code |
//! | `mkaring_maximum.exe` | Dynamic | ? | Maximum preset |

use std::{any::Any, collections::HashSet, sync::Arc};

use crate::{
    cilassembly::CleanupRequest,
    compiler::PassPhase,
    deobfuscation::{
        context::AnalysisContext,
        techniques::{
            confuserex::{
                hooks::{create_anti_tamper_stub_hook, create_lzma_hook},
                statemachine::{
                    detect_cfgctx_semantics, find_call_sites, find_constants_initializer,
                    ConfuserExStateMachine,
                },
                tamper::AntiTamperFindings,
            },
            Detection, Detections, Evidence, Technique, TechniqueCategory,
        },
    },
    metadata::{
        signatures::TypeSignature,
        tables::{FieldRvaRaw, MethodSpecRaw, TableId},
        token::Token,
    },
    CilObject,
};

/// Minimum call-site count for a method to be considered a decryptor.
const MIN_CALL_SITES: usize = 3;

/// LZMA properties byte found at the start of compressed FieldRVA data.
///
/// This is the default LZMA properties byte (`lc=3, lp=0, pb=2`) used by
/// ConfuserEx and most LZMA compressors. A fork using different LZMA settings
/// would produce a different properties byte and require updating this constant.
const LZMA_MAGIC: u8 = 0x5D;

/// Findings from constants protection detection.
#[derive(Debug)]
pub struct ConstantsFindings {
    /// Tokens of detected decryptor methods.
    pub decryptor_tokens: Vec<Token>,
    /// Whether CFG mode (order-dependent decryption) was detected.
    pub uses_cfg_mode: bool,
    /// Non-`<Module>` types containing decryptor methods.
    pub infrastructure_types: Vec<Token>,
    /// Constants Initialize() method token (LZMA decompression entry).
    pub initializer_token: Option<Token>,
    /// MethodSpec tokens referencing decryptor methods (generic instantiations).
    pub methodspec_tokens: Vec<Token>,
    /// Field tokens for FieldRVA entries with LZMA-compressed data.
    pub data_field_tokens: Vec<Token>,
    /// Types owning LZMA FieldRVA data fields (data carrier types).
    pub backing_type_tokens: Vec<Token>,
    /// CFGCtx value type token (present when CFG mode is detected).
    pub cfgctx_type_token: Option<Token>,
    /// `<Module>` fields used by decryptor infrastructure (runtime state byte[], etc.).
    /// These are non-FieldRVA fields referenced by decryptor/initializer methods.
    pub module_state_fields: Vec<Token>,
}

/// Detects ConfuserEx constants protection (string/number/array encryption).
///
/// Supersedes `generic.strings` and `generic.constants` with ConfuserEx-specific
/// detection that identifies the unified `T Get<T>(int32)` decryptor pattern,
/// LZMA-compressed FieldRVA data, and CFG mode state tracking.
pub struct ConfuserExConstants;

impl Technique for ConfuserExConstants {
    fn id(&self) -> &'static str {
        "confuserex.constants"
    }

    fn name(&self) -> &'static str {
        "ConfuserEx Constant Decryption"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Value
    }

    fn supersedes(&self) -> &[&'static str] {
        &["generic.strings", "generic.constants"]
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let mut decryptor_tokens = Vec::new();
        let mut uses_cfg_mode = false;
        let mut has_lzma_fieldrva = false;

        // Phase 1: Find decryptor methods.
        // ConfuserEx puts decryptors in <Module> or types with non-ASCII names.
        // Decryptors are static methods with signature:
        // - string(int32) — non-generic string decryptor
        // - T(int32) with generic_param_count == 1 — generic decryptor
        //
        // Note: Call-site counting is NOT used because ConfuserEx generic calls
        // use MethodSpec tokens, not MethodDef tokens directly.
        for type_entry in assembly.types().iter() {
            let cil_type = type_entry.value();

            // ConfuserEx puts decryptors in <Module> or types with non-ASCII names
            let is_module_type = cil_type.is_module_type();
            let is_obfuscated_name = !cil_type.name.is_ascii();
            if !is_module_type && !is_obfuscated_name {
                continue;
            }

            for i in 0..cil_type.methods.count() {
                let Some(method_ref) = cil_type.methods.get(i) else {
                    continue;
                };
                let Some(method) = method_ref.upgrade() else {
                    continue;
                };

                if !method.is_static() {
                    continue;
                }

                let sig = &method.signature;

                // The single parameter is an index into the constant blob. Its
                // declared width varies across ConfuserEx forks — stock 1.6.0
                // emits `int32`, others emit `uint32` — so accept any integral
                // type rather than pinning one. The surrounding constraints
                // (static, <Module> or non-ASCII owner, arity 1, string or `!!0`
                // return) carry the selectivity.
                let first_param_is_integral = sig.params.first().is_some_and(|p| {
                    matches!(
                        p.base,
                        TypeSignature::I1
                            | TypeSignature::U1
                            | TypeSignature::I2
                            | TypeSignature::U2
                            | TypeSignature::I4
                            | TypeSignature::U4
                            | TypeSignature::I8
                            | TypeSignature::U8
                            | TypeSignature::I
                            | TypeSignature::U
                    )
                });

                // Check for string(<integer>) signature
                let is_string_decryptor = sig.param_count_generic == 0
                    && sig.return_type.base == TypeSignature::String
                    && sig.params.len() == 1
                    && first_param_is_integral;

                // Check for generic T(<integer>) signature (param_count_generic == 1,
                // return type is GenericParamMethod(0))
                let is_generic_decryptor = sig.param_count_generic == 1
                    && matches!(sig.return_type.base, TypeSignature::GenericParamMethod(0))
                    && sig.params.len() == 1
                    && first_param_is_integral;

                if is_string_decryptor || is_generic_decryptor {
                    decryptor_tokens.push(method.token);
                }
            }
        }

        // Phase 2: Check for LZMA-compressed FieldRVA data and collect field tokens.
        // ConfuserEx stores the encrypted constants blob in a FieldRVA field.
        // The first byte of the data is the LZMA properties byte (0x5D).
        let mut data_field_tokens = Vec::new();
        if let Some(tables) = assembly.tables() {
            if let Some(fieldrva_table) = tables.table::<FieldRvaRaw>() {
                let file = assembly.file();
                for row in fieldrva_table {
                    let row = match row {
                        Ok(row) => row,
                        Err(e) => {
                            log::warn!("skipping unreadable metadata row: {e}");
                            continue;
                        }
                    };
                    if row.rva == 0 {
                        continue;
                    }
                    if file
                        .rva_slice(row.rva as usize, 1)
                        .is_ok_and(|data| data.first() == Some(&LZMA_MAGIC))
                    {
                        has_lzma_fieldrva = true;
                        data_field_tokens.push(Token::from_parts(TableId::Field, row.field));
                    }
                }
            }
        }

        // Phase 3: Detect CFG mode heuristically by checking for the CFGCtx value
        // type. Full SSA-based call-site classification is deferred to initialize()
        // which runs after the detection phase under the scheduler.
        if !decryptor_tokens.is_empty() {
            uses_cfg_mode = detect_cfgctx_semantics(assembly).is_some();
        }

        if decryptor_tokens.is_empty() && !has_lzma_fieldrva {
            return Detection::new_empty();
        }

        // Phase 4: Collect infrastructure types (non-<Module> types containing decryptors).
        let decryptor_set: HashSet<Token> = decryptor_tokens.iter().copied().collect();
        let mut infrastructure_types = Vec::new();
        for type_entry in assembly.types().iter() {
            let cil_type = type_entry.value();
            if cil_type.is_module_type() {
                continue;
            }
            let has_decryptor = (0..cil_type.methods.count()).any(|i| {
                cil_type
                    .methods
                    .get(i)
                    .and_then(|r| r.upgrade())
                    .is_some_and(|m| decryptor_set.contains(&m.token))
            });
            if has_decryptor {
                infrastructure_types.push(cil_type.token);
            }
        }

        // Phase 5: Collect MethodSpec tokens referencing decryptors.
        let mut methodspec_tokens = Vec::new();
        if let Some(tables) = assembly.tables() {
            if let Some(methodspec_table) = tables.table::<MethodSpecRaw>() {
                for spec in methodspec_table {
                    let spec = match spec {
                        Ok(row) => row,
                        Err(e) => {
                            log::warn!("skipping unreadable metadata row: {e}");
                            continue;
                        }
                    };
                    let references_decryptor = if decryptor_set.contains(&spec.method.token) {
                        true
                    } else if spec.method.token.is_table(TableId::MemberRef) {
                        resolve_memberref_to_decryptor(assembly, spec.method.token, &decryptor_set)
                            .is_some()
                    } else {
                        false
                    };
                    if references_decryptor {
                        methodspec_tokens.push(spec.token);
                    }
                }
            }
        }

        // Phase 6: Find parent types of LZMA data fields (backing types).
        // Only mark a backing type for deletion if ALL its fields are LZMA data fields.
        // Types like <PrivateImplementationDetails> may also contain legitimate field
        // initialization data (e.g., __StaticArrayInitTypeSize fields used by
        // RuntimeHelpers.InitializeArray) — deleting the entire type would destroy
        // that data and break reconstructed array initializers.
        let data_field_set: HashSet<Token> = data_field_tokens.iter().copied().collect();
        let infra_set: HashSet<Token> = infrastructure_types.iter().copied().collect();
        let mut backing_type_tokens = Vec::new();
        if !data_field_set.is_empty() {
            for type_entry in assembly.types().iter() {
                let cil_type = type_entry.value();
                if cil_type.is_module_type() {
                    continue;
                }
                if infra_set.contains(&cil_type.token) {
                    continue;
                }
                let field_count = cil_type.fields.iter().count();
                let lzma_field_count = cil_type
                    .fields
                    .iter()
                    .filter(|(_, field)| data_field_set.contains(&field.token))
                    .count();
                // Only delete the type if ALL its fields are LZMA data fields.
                // Types with no fields (like <PrivateImplementationDetails> which is
                // just a container for nested sized-struct types) are preserved — codegen
                // may add new fields to them for RuntimeHelpers.InitializeArray.
                if field_count > 0 && lzma_field_count == field_count {
                    backing_type_tokens.push(cil_type.token);
                }
            }
        }

        // Phase 7: Find constants initializer method.
        let initializer_token = find_constants_initializer(assembly);

        // Phase 8: Collect <Module> state fields referenced by decryptor infrastructure.
        // The runtime decryptor stores decrypted constants in a static byte[] field on
        // <Module> (the `b` field in Confuser.Runtime/Constant.cs). After SSA/codegen
        // rewrites decryptor method bodies, the original field references may be lost,
        // preventing cascade removal. Explicitly collecting these fields ensures cleanup.
        let module_state_fields = collect_module_state_fields(
            assembly,
            &decryptor_tokens,
            initializer_token,
            &data_field_set,
        );

        // Phase 9: Detect CFGCtx type for cleanup.
        let cfgctx_type_token = if uses_cfg_mode {
            detect_cfgctx_semantics(assembly).and_then(|s| s.type_token)
        } else {
            None
        };

        let mut evidence = Vec::new();

        if !decryptor_tokens.is_empty() {
            evidence.push(Evidence::Structural(format!(
                "{} decryptor methods with T(int32) signature",
                decryptor_tokens.len(),
            )));
        }
        if has_lzma_fieldrva {
            evidence.push(Evidence::Resource(
                "LZMA-compressed FieldRVA data blob".to_string(),
            ));
        }
        if uses_cfg_mode {
            evidence.push(Evidence::Structural(
                "CFG mode: order-dependent constant decryption".to_string(),
            ));
        }

        let findings = ConstantsFindings {
            decryptor_tokens,
            uses_cfg_mode,
            infrastructure_types,
            initializer_token,
            methodspec_tokens,
            data_field_tokens,
            backing_type_tokens,
            cfgctx_type_token,
            module_state_fields,
        };

        Detection::new_detected(
            evidence,
            Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
        )
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        Some(PassPhase::Value)
    }

    fn cleanup(&self, detection: &Detection) -> Option<CleanupRequest> {
        let findings = detection.findings::<ConstantsFindings>()?;
        let mut request = CleanupRequest::new();

        // Add decryptor methods for removal.
        for token in &findings.decryptor_tokens {
            request.add_method(*token);
        }

        // Add infrastructure types (cascades to delete all their members).
        for token in &findings.infrastructure_types {
            request.add_type(*token);
        }

        // Add MethodSpec tokens (generic instantiations of decryptors).
        for token in &findings.methodspec_tokens {
            request.add_methodspec(*token);
        }

        // Add constants initializer method.
        if let Some(init) = findings.initializer_token {
            request.add_method(init);
        }

        // Add LZMA FieldRVA data fields.
        for token in &findings.data_field_tokens {
            request.add_field(*token);
        }

        // Add <Module> state fields (runtime byte[] buffer, etc.).
        for token in &findings.module_state_fields {
            request.add_field(*token);
        }

        // Add backing types (data carrier types owning LZMA fields).
        for token in &findings.backing_type_tokens {
            request.add_type(*token);
        }

        // Add CFGCtx value type.
        if let Some(cfgctx) = findings.cfgctx_type_token {
            request.add_type(cfgctx);
        }

        if request.has_deletions() {
            Some(request)
        } else {
            None
        }
    }

    fn initialize(
        &self,
        ctx: &AnalysisContext,
        assembly: &CilObject,
        detection: &Detection,
        detections: &Detections,
    ) {
        let Some(findings) = detection.findings::<ConstantsFindings>() else {
            return;
        };

        if findings.decryptor_tokens.is_empty() {
            return;
        }

        // Step 1: Register decryptor methods with the analysis context so the
        // shared DecryptionPass can identify and emulate them.
        for token in &findings.decryptor_tokens {
            ctx.decryptors.register(*token);
        }

        log::info!(
            "Registered {} ConfuserEx decryptor methods (CFG mode: {})",
            findings.decryptor_tokens.len(),
            findings.uses_cfg_mode,
        );

        // Step 2: Find the constants Initialize() method for targeted warmup.
        // The Initialize() method performs LZMA decompression of the encrypted
        // constants buffer. Running it directly avoids executing anti-tamper or
        // anti-debug code that may also live in .cctor.
        if let Some(init_method) = find_constants_initializer(assembly) {
            log::info!(
                "Found constants Initialize() method 0x{:08X} — using for targeted warmup",
                init_method.value()
            );
            ctx.register_warmup_method(init_method, vec![]);
        }

        // Step 3: Register the LZMA emulation hook.
        // ConfuserEx uses an inline LZMA decompressor during initialization.
        // This hook provides native LZMA decompression instead of emulating
        // the complex algorithm instruction by instruction.
        ctx.register_emulation_hook("confuserex.constants", create_lzma_hook);

        // Step 4: Register anti-tamper stub hook if anti-tamper was detected.
        //
        // When warmup runs the Initialize() method (or .cctor), it may trigger
        // anti-tamper initialization code (DynCipher decryption). If anti-tamper
        // decryption has already run in the byte-level phase, re-executing
        // the anti-tamper init would corrupt already-decrypted method bodies.
        //
        // We stub out the anti-tamper methods so warmup skips them while still
        // running the constants initialization code.
        if let Some(tamper_findings) =
            detections.findings::<AntiTamperFindings>("confuserex.tamper")
        {
            if let Some(init_token) = tamper_findings.initializer_token {
                let mut anti_tamper_tokens = HashSet::new();
                anti_tamper_tokens.insert(init_token);
                let count = anti_tamper_tokens.len();
                ctx.register_emulation_hook("confuserex.antitamper", {
                    let tokens = anti_tamper_tokens.clone();
                    move || create_anti_tamper_stub_hook(tokens.clone())
                });
                log::info!(
                    "Registered stub hooks for {count} anti-tamper method(s) to prevent \
                     re-execution during warmup"
                );
            }
        }

        // Step 5: Register MethodSpec mappings for generic decryptors.
        // ConfuserEx generic decryptors (T Get<T>(int32)) are called via
        // MethodSpec tokens that instantiate the generic with specific types
        // (e.g., Get<string>, Get<int>). The DecryptionPass sees MethodSpec
        // tokens at call sites, so we map each back to the base decryptor.
        register_methodspec_mappings(ctx, assembly, &findings.decryptor_tokens);

        // Step 6: Register state machine provider if CFG mode detected.
        // CFG mode uses a CFGCtx value type with a multiplicative hash chain
        // to make constant decryption order-dependent per method.
        if findings.uses_cfg_mode {
            let semantics = detect_cfgctx_semantics(assembly);
            if let Some(semantics) = semantics {
                // Find which methods use the state machine.
                let call_sites = find_call_sites(assembly, &findings.decryptor_tokens);
                let cfg_mode_methods: HashSet<Token> = call_sites
                    .iter()
                    .filter(|site| site.uses_statemachine)
                    .map(|site| site.caller)
                    .collect();

                if !cfg_mode_methods.is_empty() {
                    let method_count = cfg_mode_methods.len();
                    let provider =
                        ConfuserExStateMachine::new(semantics, cfg_mode_methods.iter().copied());
                    ctx.register_statemachine_provider(Arc::new(provider));

                    log::info!(
                        "CFG mode detected: {method_count} methods require order-dependent \
                         decryption"
                    );
                }
            }
        }
    }
}

/// Registers `MethodSpec → base decryptor` mappings in the analysis context.
///
/// ConfuserEx generic decryptors (`T Get<T>(int32)`) are called via `MethodSpec`
/// tokens that instantiate the generic with a specific type (e.g., `Get<string>`).
/// The `DecryptionPass` sees the `MethodSpec` token at the call site rather than
/// the base `MethodDef`, so each spec must be mapped back to its decryptor so
/// the pass can identify calls to emulate.
///
/// # Arguments
///
/// * `ctx` - The analysis context that owns the decryptor registry.
/// * `assembly` - The assembly, used to resolve `MethodSpec` and `MemberRef` tables.
/// * `decryptor_tokens` - Slice of known decryptor `MethodDef` tokens.
fn register_methodspec_mappings(
    ctx: &AnalysisContext,
    assembly: &CilObject,
    decryptor_tokens: &[Token],
) {
    let decryptor_set: HashSet<Token> = decryptor_tokens.iter().copied().collect();

    let Some(tables) = assembly.tables() else {
        return;
    };
    let Some(methodspec_table) = tables.table::<MethodSpecRaw>() else {
        return;
    };

    for methodspec in methodspec_table {
        let methodspec = match methodspec {
            Ok(row) => row,
            Err(e) => {
                log::warn!("skipping unreadable metadata row: {e}");
                continue;
            }
        };
        let method_token = methodspec.method.token;

        // Check if this MethodSpec references a known decryptor.
        // The method field is a MethodDefOrRef coded index — it can be
        // a direct MethodDef reference or a MemberRef.
        let base_decryptor = if decryptor_set.contains(&method_token) {
            Some(method_token)
        } else if method_token.is_table(TableId::MemberRef) {
            resolve_memberref_to_decryptor(assembly, method_token, &decryptor_set)
        } else {
            None
        };

        if let Some(decryptor) = base_decryptor {
            ctx.decryptors.map_methodspec(methodspec.token, decryptor);
        }
    }
}

/// Collects `<Module>` fields referenced by decryptor infrastructure methods.
///
/// The ConfuserEx runtime stores decrypted constants in a `static byte[] b` field
/// on `<Module>`. After SSA/codegen rewrites the decryptor method bodies, the
/// original `ldsfld`/`stsfld` references may be lost, preventing cascade removal
/// during cleanup. This function scans the original IL of decryptor and initializer
/// methods to find all `<Module>` field references, excluding FieldRVA data fields
/// (which are handled separately).
fn collect_module_state_fields(
    assembly: &CilObject,
    decryptor_tokens: &[Token],
    initializer_token: Option<Token>,
    data_field_set: &HashSet<Token>,
) -> Vec<Token> {
    // Build the set of <Module> field tokens
    let mut module_fields = HashSet::new();
    for entry in assembly.types().iter() {
        if entry.value().is_module_type() {
            for field in entry.value().fields() {
                module_fields.insert(field.token);
            }
            break;
        }
    }

    if module_fields.is_empty() {
        return Vec::new();
    }

    // Scan IL of decryptor and initializer methods for field references
    let mut state_fields = HashSet::new();
    let method_tokens: Vec<Token> = decryptor_tokens
        .iter()
        .copied()
        .chain(initializer_token)
        .collect();

    for method_token in &method_tokens {
        let Ok(method) = assembly.method(method_token) else {
            continue;
        };
        for instr in method.instructions() {
            if let Some(token) = instr.get_token_operand() {
                if token.table() == 0x04
                    && module_fields.contains(&token)
                    && !data_field_set.contains(&token)
                {
                    state_fields.insert(token);
                }
            }
        }
    }

    state_fields.into_iter().collect()
}

/// Attempts to resolve a `MemberRef` token to a known decryptor `MethodDef`.
///
/// Resolves the `MemberRef` via [`CilObject::member_ref`] and checks whether
/// its name matches any known decryptor. This handles the case where a
/// `MethodSpec` references the decryptor through a `MemberRef` rather than
/// directly by `MethodDef` token.
///
/// # Arguments
///
/// * `assembly` - The assembly, used to resolve the `MemberRef`.
/// * `memberref_token` - The `MemberRef` token to resolve.
/// * `decryptor_set` - Set of known decryptor `MethodDef` tokens to match against.
///
/// # Returns
///
/// `Some(decryptor_token)` if the `MemberRef` name matches a known decryptor,
/// `None` if the token does not resolve or no name match is found.
fn resolve_memberref_to_decryptor(
    assembly: &CilObject,
    memberref_token: Token,
    decryptor_set: &HashSet<Token>,
) -> Option<Token> {
    let memberref = assembly.member_ref(&memberref_token)?;

    for decryptor_token in decryptor_set {
        if let Ok(method) = assembly.method(decryptor_token) {
            if method.name == memberref.name {
                return Some(*decryptor_token);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::techniques::{
            confuserex::constants::{ConfuserExConstants, ConstantsFindings},
            Technique,
        },
        testkit::helpers::load_sample,
    };

    #[test]
    fn test_detect_positive() {
        let assembly = load_sample("packers/confuserex/1.6.0/mkaring_constants.exe");

        let technique = ConfuserExConstants;
        let detection = technique.detect(&assembly);

        assert!(
            detection.is_detected(),
            "ConfuserExConstants should detect constants protection in mkaring_constants.exe"
        );
        assert!(
            !detection.evidence().is_empty(),
            "Detection should have evidence"
        );

        let findings = detection
            .findings::<ConstantsFindings>()
            .expect("Should have ConstantsFindings");

        assert!(
            !findings.decryptor_tokens.is_empty(),
            "Should have decryptor method tokens"
        );
    }

    #[test]
    fn test_detect_negative() {
        let assembly = load_sample("packers/confuserex/1.6.0/original.exe");

        let technique = ConfuserExConstants;
        let detection = technique.detect(&assembly);

        assert!(
            !detection.is_detected(),
            "ConfuserExConstants should not detect constants protection in original.exe"
        );
    }
}

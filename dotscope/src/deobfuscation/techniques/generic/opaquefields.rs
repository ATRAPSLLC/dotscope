//! Opaque field predicate detection via SSA analysis.
//!
//! Detects two variants of opaque predicates:
//!
//! ## Variant A: Static field → instance field chain
//!
//! ```text
//! v1 = LoadStaticField(static_field)     // ldsfld <Module>::<instance>
//! v2 = LoadField(v1, instance_field)     // ldfld <int32_field>
//! Branch(condition=v2, true_target, false_target)
//! ```
//!
//! The singleton objects are initialized in type constructors (`.cctor`s). By
//! emulating those constructors, the actual field values can be determined and
//! conditional branches replaced with unconditional jumps.
//!
//! ## Variant B: Sentinel null-check methods
//!
//! ```text
//! // Sentinel method body (4 instructions):
//! v0 = LoadStaticField(self_typed_field)  // ldsfld <Module>::field
//! v1 = Const(Null)                        // ldnull
//! v2 = Ceq(v0, v1)                        // ceq
//! Return(v2)                               // ret → always true (field is null)
//!
//! // Call site:
//! v3 = Call(sentinel_method)               // call bool SentinelMethod()
//! Branch(condition=v3, ...)                 // brtrue/brfalse
//! ```
//!
//! Sentinel fields are self-typed static references that are never written to
//! in most cases, but may be resolved via Reflection at runtime. Emulation
//! determines their actual value safely.
//!
//! # Detection
//!
//! Detection uses `detect_ssa()` (Phase 3.5) to scan SSA functions for both
//! patterns. Variant A uses `LoadStaticField → LoadField → Branch` def-use
//! chains. Variant B identifies sentinel methods by their body pattern, then
//! finds call sites.
//!
//! # Passes
//!
//! Creates an `OpaqueFieldPredicatePass` with pre-computed findings from the
//! SSA detection phase, avoiding a redundant SSA scan in the pass's
//! `initialize()`.

use std::{
    any::Any,
    collections::{HashMap, HashSet},
    sync::Arc,
};

use crate::{
    analysis::{CilTarget, SsaFunction, SsaOp, SsaOpCilExt, SsaVarId},
    cilassembly::CleanupRequest,
    compiler::{CompilerContext, PassPhase, SsaPass},
    deobfuscation::{
        context::AnalysisContext,
        passes::OpaqueFieldPredicatePass,
        techniques::{Detection, Detections, Evidence, Technique, TechniqueCategory},
        utils::build_def_map,
    },
    emulation::{EmValue, Hook, HookPriority, PreHookResult},
    metadata::{tables::TableId, token::Token},
    CilObject,
};

/// Scans an SSA function for the opaque predicate pattern and collects the
/// static field tokens that appear in `LoadStaticField -> LoadField -> Branch`.
///
/// Builds a definition map and then traces each `Branch` terminator's condition
/// backwards through `LoadField` and `LoadStaticField` to extract the static
/// field tokens. Returns the set of all such tokens found in the function.
fn collect_predicate_static_fields(ssa: &SsaFunction) -> HashSet<Token> {
    let defs = build_def_map(ssa);

    let mut static_fields = HashSet::new();
    for block in ssa.blocks() {
        let Some(terminator) = block.control_terminator() else {
            continue;
        };

        // Match: Branch { condition, .. }
        let condition = match terminator {
            SsaOp::Branch { condition, .. } => *condition,
            _ => continue,
        };

        // Trace condition → LoadField { object, .. }
        let Some(SsaOp::LoadField { object, .. }) = defs.get(&condition) else {
            continue;
        };

        // Trace object → LoadStaticField { field }
        let Some(SsaOp::LoadStaticField { field, .. }) = defs.get(object) else {
            continue;
        };

        static_fields.insert(field.token());
    }
    static_fields
}

/// Collects every field token written by a `StoreField`/`StoreStaticField` anywhere in `ssa`.
///
/// A field that is assigned after its declaring constructor has run cannot be folded to a
/// constant: the value observed at `.cctor` warm-up time is not the value the program sees.
/// Callers use this across *every* SSA function in the assembly, because the write that
/// invalidates a fold is frequently in a different method from the read.
fn collect_field_stores(ssa: &SsaFunction) -> HashSet<Token> {
    let mut stored = HashSet::new();
    for block in ssa.blocks() {
        for instr in block.instructions() {
            match instr.op() {
                SsaOp::StoreField { field, .. } | SsaOp::StoreStaticField { field, .. } => {
                    stored.insert(field.token());
                }
                _ => {}
            }
        }
    }
    stored
}

/// Collects methods that only ever execute as part of type initialization.
///
/// Stores made while a type initializes must not count against a field's immutability —
/// that store is what gives the field its constant value. Matching the `.cctor` name alone
/// is too narrow: an obfuscator can put the stores in a plain static helper and call it from
/// `.cctor`, which is exactly what .NET Reactor does with its key containers. A method whose
/// every caller is itself initialization-only runs only during initialization too, so the set
/// is closed under that rule and grown to a fixed point.
///
/// A method with no recorded callers is not admitted: unreachable in the SSA call graph is not
/// the same as reachable only from `.cctor`, and assuming otherwise would admit any method the
/// analysis simply failed to see a caller for.
fn collect_initialization_only_methods(
    ctx: &AnalysisContext,
    assembly: &CilObject,
) -> HashSet<Token> {
    let mut callers: HashMap<Token, HashSet<Token>> = HashMap::new();
    let mut methods: Vec<Token> = Vec::new();

    for entry in ctx.ssa_functions.iter() {
        let caller = *entry.key();
        methods.push(caller);
        for block in entry.value().blocks() {
            for instr in block.instructions() {
                let callee = match instr.op() {
                    SsaOp::LoadFunctionPtr { method, .. }
                    | SsaOp::LoadVirtFunctionPtr { method, .. } => method.token(),
                    SsaOp::NewObj { ctor, .. } => ctor.token(),
                    op => match op.method_call() {
                        Some((token, _)) => token,
                        None => continue,
                    },
                };
                callers.entry(callee).or_default().insert(caller);
            }
        }
    }

    let mut init_only: HashSet<Token> = methods
        .iter()
        .copied()
        .filter(|token| is_static_constructor(assembly, *token))
        .collect();

    loop {
        let mut grew = false;
        for &method in &methods {
            if init_only.contains(&method) {
                continue;
            }
            let Some(method_callers) = callers.get(&method) else {
                continue;
            };
            if !method_callers.is_empty() && method_callers.iter().all(|c| init_only.contains(c)) {
                init_only.insert(method);
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }

    init_only
}

/// Returns whether `token` names a static constructor.
///
/// Used to exclude `.cctor` bodies from the assembly-wide store scan: an `initonly` static is
/// assigned there by definition, so counting those stores would disqualify every field the
/// immutability gate is meant to admit.
fn is_static_constructor(assembly: &CilObject, token: Token) -> bool {
    assembly
        .resolve_method_name(token)
        .is_some_and(|name| name == ".cctor")
}

/// Scans an SSA function for ALL `LoadField(LoadStaticField(..))` patterns
/// and collects the static field tokens.
///
/// Unlike [`collect_predicate_static_fields`] which only looks at Branch
/// terminators, this function scans every instruction. It captures both
/// opaque predicate fields AND string encryption XOR key fields.
///
/// # Why callers must gate the result
///
/// This matches the plain singleton-access idiom (`Config.Instance.Retries`) just as readily as
/// an opaque predicate — `ldsfld; ldfld` is not an obfuscation signature. Folding an unfiltered
/// match set freezes mutable state at its constructor-time value, turning branches that depend
/// on runtime state into unconditional jumps to the wrong successor. Every caller therefore
/// filters through [`collect_field_stores`].
fn collect_field_load_sources(ssa: &SsaFunction) -> HashSet<Token> {
    let defs = build_def_map(ssa);

    let mut static_fields = HashSet::new();
    for block in ssa.blocks() {
        for instr in block.instructions() {
            // Match: LoadField { object, .. }
            let SsaOp::LoadField { object, .. } = instr.op() else {
                continue;
            };

            // Trace object → LoadStaticField { field }
            let Some(SsaOp::LoadStaticField { field, .. }) = defs.get(object) else {
                continue;
            };

            static_fields.insert(field.token());
        }
    }
    static_fields
}

/// Checks if an SSA function matches the sentinel null-check method pattern:
///
/// ```text
/// v0 = LoadStaticField { field }   // ldsfld self_typed_field
/// v1 = Const { value: Null }       // ldnull
/// v2 = Ceq { left: v0, right: v1 } // ceq
/// Return { value: Some(v2) }        // ret
/// ```
///
/// Returns `Some(field_token)` if the pattern matches, `None` otherwise.
/// The detection follows def-use chains from the Return terminator backwards,
/// so it's insensitive to instruction ordering and tolerates Nop/Phi padding.
fn identify_sentinel_method(ssa: &SsaFunction) -> Option<Token> {
    // Sentinel methods are tiny — reject anything with more than 2 blocks
    // (entry + possible unreachable) or too many instructions.
    if ssa.block_count() > 2 {
        return None;
    }

    let block = ssa.blocks().first()?;

    // Find the Return terminator
    let terminator = block.control_terminator()?;
    let return_var = match terminator {
        SsaOp::Return { value: Some(v), .. } => *v,
        _ => return None,
    };

    // Build def map for this block
    let mut defs: HashMap<SsaVarId, &SsaOp> = HashMap::new();
    for instr in block.instructions() {
        if let Some(dest) = instr.op().dest() {
            defs.insert(dest, instr.op());
        }
    }

    // Trace return_var → Ceq { left, right }
    let (left, right) = match defs.get(&return_var)? {
        SsaOp::Ceq { left, right, .. } => (*left, *right),
        _ => return None,
    };

    // One operand must be LoadStaticField, the other must be Const(Null).
    // The token in `LoadStaticField` may be a FieldDef (0x04) or a MemberRef
    // (0x0A) per ECMA-335 — only the former is deletable from this assembly,
    // so reject MemberRefs here. A sentinel field is, by construction, a
    // private static FieldDef of the protector; a MemberRef-resolved sentinel
    // would imply the field lives in another assembly, which we cannot delete.
    let field_token = match (defs.get(&left), defs.get(&right)) {
        (Some(SsaOp::LoadStaticField { field, .. }), Some(SsaOp::Const { value, .. }))
            if value.is_null() =>
        {
            field.token()
        }
        (Some(SsaOp::Const { value, .. }), Some(SsaOp::LoadStaticField { field, .. }))
            if value.is_null() =>
        {
            field.token()
        }
        _ => return None,
    };
    if !field_token.is_table(TableId::Field) {
        return None;
    }

    // Verify the method is small (no more than ~8 real instructions, excluding phis/nops)
    let real_instructions = block
        .instructions()
        .iter()
        .filter(|i| !matches!(i.op(), SsaOp::Nop | SsaOp::Phi { .. }))
        .count();
    if real_instructions > 6 {
        return None;
    }

    Some(field_token)
}

/// Scans all SSA functions to find sentinel null-check methods and their call sites.
///
/// Returns:
/// - `sentinel_methods`: Map of sentinel method token → sentinel field token
/// - `sentinel_call_sites`: Set of method tokens that call sentinel methods
fn collect_sentinel_info(
    ssa_functions: &dashmap::DashMap<Token, SsaFunction>,
) -> (HashMap<Token, Token>, HashSet<Token>) {
    // Phase 1: Identify sentinel methods by their body pattern
    let mut sentinel_methods: HashMap<Token, Token> = HashMap::new();
    for entry in ssa_functions.iter() {
        if let Some(field_token) = identify_sentinel_method(entry.value()) {
            sentinel_methods.insert(*entry.key(), field_token);
        }
    }

    if sentinel_methods.is_empty() {
        return (sentinel_methods, HashSet::new());
    }

    // Phase 2: Find call sites that reference sentinel methods
    let mut call_site_methods: HashSet<Token> = HashSet::new();
    for entry in ssa_functions.iter() {
        let method_token = *entry.key();
        if sentinel_methods.contains_key(&method_token) {
            continue;
        }
        let has_sentinel_call = entry.value().blocks().iter().any(|block| {
            block.instructions().iter().any(|instr| {
                instr
                    .op()
                    .method_call()
                    .is_some_and(|(token, _)| sentinel_methods.contains_key(&token))
            })
        });
        if has_sentinel_call {
            call_site_methods.insert(method_token);
        }
    }

    (sentinel_methods, call_site_methods)
}

/// Findings from opaque field predicate detection.
#[derive(Debug)]
pub struct OpaquePredicateFindings {
    /// Unique static field tokens appearing in opaque predicate patterns (Variant A).
    pub affected_field_tokens: Vec<Token>,
    /// Method tokens that contain at least one opaque predicate (Variant A or B call site).
    pub affected_methods: Vec<Token>,
    /// TypeDef tokens of types that own the detected opaque predicate fields.
    /// Used by `cleanup()` to request removal of the GUID class.
    pub owning_type_tokens: Vec<Token>,
    /// Sentinel method token → sentinel field token mapping (Variant B).
    /// The method body is `ldsfld → ldnull → ceq → ret` (always returns true if field is null).
    pub sentinel_methods: HashMap<Token, Token>,
}

/// Detects static field chain opaque predicates via SSA def-use analysis.
pub struct GenericOpaquePredicates;

impl Technique for GenericOpaquePredicates {
    fn id(&self) -> &'static str {
        "generic.opaquefields"
    }

    fn name(&self) -> &'static str {
        "Opaque Field Predicates"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Structure
    }

    fn detect(&self, _assembly: &CilObject) -> Detection {
        // IL-level detection is not used — all detection happens in detect_ssa()
        // after SSA functions are built, where we can follow exact def-use chains.
        Detection::new_empty()
    }

    fn detect_ssa(&self, ctx: &AnalysisContext, assembly: &CilObject) -> Detection {
        // Variant A: Static field chain predicates
        let mut affected_fields: HashSet<Token> = HashSet::new();
        let mut affected_methods: HashSet<Token> = HashSet::new();

        // Every field written anywhere in the assembly *except* in a static constructor. A
        // store in one method invalidates a fold of the same field in another, so this has to
        // be assembly-wide rather than per-method — and it must be collected before any
        // folding decision is made.
        //
        // Initialization is excluded deliberately, and the gate below does not work without
        // it: the pass warms those initializers up precisely so their values are known
        // constants, so a store there is what makes a field foldable, not what disqualifies
        // it. Counting them would leave `all_field_loads` permanently empty and silently
        // disable Variant A's field-load detection entirely.
        //
        // The exclusion covers every initialization-only method, not just `.cctor` itself —
        // see [`collect_initialization_only_methods`]. .NET Reactor's `.cctor` calls a plain
        // static helper that does the stores, so a name-based test counts them and judges the
        // key fields mutable.
        let init_only = collect_initialization_only_methods(ctx, assembly);
        let mut stored_fields: HashSet<Token> = HashSet::new();
        for entry in ctx.ssa_functions.iter() {
            if init_only.contains(entry.key()) {
                continue;
            }
            stored_fields.extend(collect_field_stores(entry.value()));
        }

        for entry in ctx.ssa_functions.iter() {
            let method_token = *entry.key();
            let predicate_fields = collect_predicate_static_fields(entry.value());

            // `collect_field_load_sources` matches the ordinary singleton idiom as well as
            // opaque predicates, so admit a field only when it is provably immutable: never
            // stored outside the `.cctor`s this pass warms up (see the `.cctor` exclusion
            // where `stored_fields` is built). Without that condition the fold silently
            // freezes runtime-mutated state.
            //
            // Absence from `stored_fields` is the whole proof. Requiring the `initonly` flag
            // as well proves nothing extra -- an `initonly` field is a field the compiler
            // already refused to store outside the initializer, so it is a subset of what the
            // scan admits -- while excluding every obfuscator that assigns in `.cctor` without
            // setting the flag. .NET Reactor is one: its string-decryptor key fields are
            // `static` (0x0013) with `initonly` (0x20) clear, so demanding the flag refused
            // every fold and left the decryptor's arguments non-constant.
            let all_field_loads: HashSet<Token> = collect_field_load_sources(entry.value())
                .into_iter()
                .filter(|token| !stored_fields.contains(token))
                .collect();

            let combined: HashSet<Token> =
                predicate_fields.union(&all_field_loads).copied().collect();
            if !combined.is_empty() {
                affected_methods.insert(method_token);
                affected_fields.extend(combined);
            }
        }

        // Variant B: Sentinel null-check methods
        let (sentinel_methods, sentinel_call_sites) = collect_sentinel_info(&ctx.ssa_functions);

        // Merge sentinel call site methods into affected_methods
        affected_methods.extend(&sentinel_call_sites);

        // Merge sentinel field tokens into affected_fields for warmup targeting
        let sentinel_field_tokens: HashSet<Token> = sentinel_methods.values().copied().collect();
        affected_fields.extend(&sentinel_field_tokens);

        if affected_methods.is_empty() {
            return Detection::new_empty();
        }

        // Resolve Variant A field tokens (NOT sentinel) to FieldDef for type lookup.
        // Only Variant A fields contribute to owning_type_tokens because those types
        // (e.g., Module singleton) exist solely for opaque predicates. Sentinel fields
        // are injected into real application types which must NOT be deleted.
        let variant_a_fields: HashSet<Token> = affected_fields
            .difference(&sentinel_field_tokens)
            .copied()
            .collect();
        let mut resolved_fields: HashSet<Token> = HashSet::new();
        for token in &variant_a_fields {
            resolved_fields.insert(*token);
            if token.is_table(TableId::MemberRef) {
                if let Some(resolved) = assembly.resolver().resolve_field(*token) {
                    resolved_fields.insert(resolved);
                }
            }
        }

        // Find types that own the Variant A opaque predicate fields.
        // These types exist solely as opaque predicate infrastructure and can be deleted.
        //
        // Deletion is whole-type and `build_cleanup_request` merges a type-only request
        // unconditionally, so the bar is higher than for folding: require that *every* static
        // field the type declares was resolved as predicate infrastructure. A type with even
        // one unrelated static field is a real type that something else may still reference,
        // and removing its methods and fields would leave surviving call sites dangling.
        let mut owning_types: HashSet<Token> = HashSet::new();
        let registry = assembly.types();
        for entry in registry.iter() {
            let type_ref = entry.value();
            let mut static_fields = type_ref
                .fields
                .iter()
                .filter(|(_, field)| field.flags.is_static())
                .peekable();

            if static_fields.peek().is_none() {
                continue;
            }

            if static_fields.all(|(_, field)| resolved_fields.contains(&field.token)) {
                owning_types.insert(*entry.key());
            }
        }

        let method_count = affected_methods.len();
        let field_count = affected_fields.len();
        let sentinel_count = sentinel_methods.len();

        let mut evidence = vec![Evidence::Structural(format!(
            "{method_count} methods with opaque predicates ({field_count} unique fields)"
        ))];
        if sentinel_count > 0 {
            evidence.push(Evidence::Structural(format!(
                "{sentinel_count} sentinel null-check methods with {} call sites",
                sentinel_call_sites.len()
            )));
        }

        let findings = OpaquePredicateFindings {
            affected_field_tokens: affected_fields.into_iter().collect(),
            affected_methods: affected_methods.into_iter().collect(),
            owning_type_tokens: owning_types.into_iter().collect(),
            sentinel_methods,
        };

        Detection::new_detected(
            evidence,
            Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
        )
    }

    fn initialize(
        &self,
        ctx: &AnalysisContext,
        assembly: &CilObject,
        detection: &Detection,
        _detections: &Detections,
    ) {
        let Some(findings) = detection.findings::<OpaquePredicateFindings>() else {
            return;
        };

        // Resolve MemberRef tokens to FieldDef tokens so we can match against type fields.
        let mut resolved_fields: HashSet<Token> = HashSet::new();
        for token in &findings.affected_field_tokens {
            resolved_fields.insert(*token);
            if token.is_table(TableId::MemberRef) {
                if let Some(resolved) = assembly.resolver().resolve_field(*token) {
                    resolved_fields.insert(resolved);
                }
            }
        }

        // Find cctors for types owning the detected fields and register them as warmup methods.
        let registry = assembly.types();
        for entry in registry.iter() {
            let type_ref = entry.value();
            let owns_needed_field = type_ref.fields.iter().any(|(_, field)| {
                field.flags.is_static() && resolved_fields.contains(&field.token)
            });
            if owns_needed_field {
                if let Some(cctor) = type_ref.cctor() {
                    ctx.register_warmup_method(cctor, vec![]);
                }
            }
        }

        // Register bypass-tamper hook so the Module cctor completes in DecryptionPass.
        // The cctor may call RSACryptoServiceProvider.VerifyHash for integrity checks
        // which would fail in the emulator.
        ctx.register_emulation_hook("generic.opaquefields", || {
            Hook::new("bypass-tamper-verify-hash")
                .match_name(
                    "System.Security.Cryptography",
                    "RSACryptoServiceProvider",
                    "VerifyHash",
                )
                .with_priority(HookPriority::HIGH)
                .pre(|_ctx, _thread| PreHookResult::Bypass(Some(EmValue::I32(1))))
        });
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        Some(PassPhase::Structure)
    }

    fn create_pass(
        &self,
        ctx: &AnalysisContext,
        detection: &Detection,
        _assembly: &Arc<CilObject>,
    ) -> Vec<Box<dyn SsaPass<CilTarget, CompilerContext>>> {
        let Some(pool) = ctx.template_pool.get().cloned() else {
            return Vec::new();
        };
        let Some(findings) = detection.findings::<OpaquePredicateFindings>() else {
            return Vec::new();
        };
        let needed_static_fields: HashSet<Token> =
            findings.affected_field_tokens.iter().copied().collect();
        let affected_methods: HashSet<Token> = findings.affected_methods.iter().copied().collect();
        vec![Box::new(OpaqueFieldPredicatePass::new(
            pool,
            needed_static_fields,
            affected_methods,
            findings.sentinel_methods.clone(),
        ))]
    }

    fn cleanup(&self, detection: &Detection) -> Option<CleanupRequest> {
        let findings = detection.findings::<OpaquePredicateFindings>()?;
        let has_types = !findings.owning_type_tokens.is_empty();
        let has_sentinel = !findings.sentinel_methods.is_empty();

        if !has_types && !has_sentinel {
            return None;
        }

        let mut request = CleanupRequest::new();

        // Variant A: Remove entire owning types (Module singleton class)
        for &type_token in &findings.owning_type_tokens {
            request.add_type(type_token);
        }

        // Variant B: Remove individual sentinel methods and fields
        // (Can't remove owning types — sentinel artifacts are injected into real types)
        request.add_methods(findings.sentinel_methods.keys().copied());
        request.add_fields(findings.sentinel_methods.values().copied());

        Some(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        compiler::PassPhase,
        deobfuscation::techniques::{Technique, TechniqueCategory},
        testkit::helpers::load_sample,
    };

    /// Pins the contract that the non-SSA `detect` entry point reports nothing.
    ///
    /// This is **not** a negative test for opaque-predicate detection, despite how the previous
    /// version of it read. `detect` returns [`Detection::new_empty`] unconditionally — real
    /// detection happens in `detect_ssa`, which needs def-use chains — so asserting
    /// "nothing detected" here passes for every input, obfuscated or not, and cannot fail.
    ///
    /// Kept, narrowed, and renamed so it documents the contract instead of implying coverage
    /// that does not exist. Genuine negative coverage for `detect_ssa` requires an
    /// `AnalysisContext` with built SSA functions and belongs in the integration suite.
    #[test]
    fn detect_without_ssa_reports_nothing_by_contract() {
        let asm = load_sample("packers/confuserex/1.6.0/original.exe");

        let technique = GenericOpaquePredicates;
        let detection = technique.detect(&asm);

        assert!(
            !detection.is_detected(),
            "the non-SSA entry point defers to detect_ssa and must report nothing"
        );
        assert!(detection.evidence().is_empty());
        assert!(detection.findings::<OpaquePredicateFindings>().is_none());
    }

    // A second sample-loading copy of the above was removed rather than renamed: it asserted
    // the same unconditional-empty contract through a different sample and so added no
    // coverage, only the appearance of it plus a sample load.

    #[test]
    fn test_technique_metadata() {
        let technique = GenericOpaquePredicates;
        assert_eq!(technique.id(), "generic.opaquefields");
        assert_eq!(technique.name(), "Opaque Field Predicates");
        assert_eq!(technique.category(), TechniqueCategory::Structure);
        assert!(technique.supersedes().is_empty());
    }

    #[test]
    fn test_technique_ssa_phase() {
        let technique = GenericOpaquePredicates;
        assert_eq!(
            technique.ssa_phase(),
            Some(PassPhase::Structure),
            "GenericOpaquePredicates should run in the Structure SSA phase"
        );
    }

    /// The `.cctor` exclusion that keeps Variant A's immutability gate satisfiable.
    ///
    /// The gate admits a static field only when it is `initonly` *and* never stored. An
    /// `initonly` static can only be assigned in its declaring type's `.cctor`, so unless
    /// `.cctor` stores are excluded from the store scan the two halves are mutually exclusive,
    /// the candidate set is always empty, and field-load detection is dead code that no
    /// assertion in this suite would notice. This pins the predicate that exclusion rests on.
    #[test]
    fn static_constructors_are_identified_for_the_store_scan() {
        let asm = load_sample("packers/confuserex/1.6.0/original.exe");

        let cctors: Vec<_> = asm
            .query_methods()
            .static_constructors()
            .into_iter()
            .collect();
        assert!(
            !cctors.is_empty(),
            "sample must contain at least one .cctor for this test to mean anything"
        );
        for cctor in &cctors {
            assert!(
                is_static_constructor(&asm, cctor.token),
                "a .cctor must be excluded from the assembly-wide store scan"
            );
        }

        let non_cctors: Vec<_> = asm
            .query_methods()
            .filter(|m| !m.is_cctor())
            .into_iter()
            .take(8)
            .collect();
        assert!(!non_cctors.is_empty());
        for method in &non_cctors {
            assert!(
                !is_static_constructor(&asm, method.token),
                "an ordinary method's stores must still invalidate a fold"
            );
        }
    }
}

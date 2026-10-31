//! Generic cleanup utilities for deobfuscation.
//!
//! This module provides deobfuscation-specific cleanup operations that build on
//! the generic [`cilassembly::cleanup`](crate::cilassembly::cleanup) infrastructure.
//!
//! The deobfuscation cleanup adds:
//! - Dead method collection from analysis
//! - Entry point protection (preserves public methods, constructors, etc.)
//! - Obfuscated name renaming
//! - Event logging for statistics
//!
//! # Usage
//!
//! Obfuscator-specific modules should:
//! 1. Detect what tokens need to be removed (types, methods, fields)
//! 2. Create a [`CleanupRequest`](crate::cilassembly::CleanupRequest) with those tokens
//! 3. Call [`execute_cleanup`] to perform the cleanup
//!
//! # Example
//!
//! The `examples::module_example` test in this module runs this example.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::{
    analysis::{SsaOpCilExt, SsaVarId, TypeContext, VariableOrigin},
    assembly::Operand,
    cilassembly::{
        compute_entry_points, expand_type_tokens, find_unreferenced_types, CleanupRequest,
        GeneratorConfig, TypeNames,
    },
    compiler::{EventKind, ProxyDevirtualizationPass},
    deobfuscation::{
        context::AnalysisContext,
        engine::DeobfuscationEngine,
        renamer, repairs,
        techniques::{Detections, Technique, TechniqueCapability},
    },
    metadata::{
        tables::TableId, token::Token, typesystem::wellknown, validation::ValidationConfig,
    },
    CilObject, Result,
};

/// The message of the [`EventKind::ArtifactRemoved`] event for a method that goes because a
/// pass inlined every call to it (folded a constant it returns, forwarded a stub, dropped a
/// call to a method that does nothing): a method of the program whose code now lives in its
/// callers, rather than one of the protection's. Default cleanup removes these too.
pub const INLINED_METHOD_REMOVED: &str = "Removing method: every call to it was inlined";

/// Returns the registered decryptors that still have call sites in the
/// post-pass call graph.
///
/// Decryption rewrites a call site into the constant it produced, so a
/// decryptor nothing calls any more has been fully reversed and its
/// infrastructure can go. One that is still called has not been reversed -
/// whether because emulation failed, or because the call site was never
/// reached - and neither it nor the type that owns it may be deleted.
///
/// Generic decryptors are invoked through `MethodSpec` tokens rather than the
/// `MethodDef` directly, so each callee is resolved back to its base decryptor.
fn decryptors_still_called(
    ctx: &AnalysisContext,
    ssa_call_graph: &BTreeMap<Token, BTreeSet<Token>>,
) -> HashSet<Token> {
    let mut still_called = HashSet::new();
    for callees in ssa_call_graph.values() {
        for callee in callees {
            if let Some(decryptor) = ctx.decryptors.resolve_decryptor(*callee) {
                still_called.insert(decryptor);
            }
        }
    }
    still_called
}
/// Builds a complete cleanup request from detection results and analysis state.
///
/// This consolidates all cleanup sources into a single request:
/// 1. Merges technique-specific cleanup requests (from each detected technique)
/// 2. Adds removable decryptors (fully-emulated, safe to remove)
/// 3. Adds unreferenced infrastructure types (detected via call graph analysis)
/// 4. Adds dead methods (if aggressive mode enabled)
/// 5. Adds neutralized tokens as cascade candidates
/// 6. Sweeps empty module methods
///
/// The resulting request is complete - it can be used for both neutralization
/// (to know which tokens to neutralize) and final cleanup (to perform deletions).
///
/// # Arguments
///
/// * `engine` - The deobfuscation engine (provides technique registry).
/// * `ctx` - The analysis context containing SSA functions, dead methods, and config.
/// * `detections` - The detection results from all techniques.
/// * `assembly` - The assembly being deobfuscated.
/// * `ssa_call_graph` - The SSA-derived call graph (caller → callees).
pub(crate) fn build_cleanup_request(
    engine: &DeobfuscationEngine,
    ctx: &AnalysisContext,
    detections: &Detections,
    assembly: &CilObject,
    ssa_call_graph: &BTreeMap<Token, BTreeSet<Token>>,
) -> CleanupRequest {
    // Start with technique-merged cleanup
    let registry = engine.technique_registry();

    // Byte transforms that were detected but did not succeed.
    //
    // A byte transform rewrites the assembly before SSA is built - decrypting
    // method bodies, unpacking resources. When one fails, the assembly still
    // holds the protected form, but every technique's cleanup request was
    // already filled during detection on the assumption it would not. Merging
    // those requests deletes the infrastructure the protected code still needs.
    //
    // Failure is recorded by omission: the pipeline calls `mark_transformed`
    // only on success and logs the error, so "detected, declares a byte
    // transform, not transformed" is the signal. Techniques without the
    // capability are never marked and must not be caught by this.
    let failed: Vec<&dyn Technique> = registry
        .sorted_techniques(detections)
        .into_iter()
        .filter(|tech| {
            tech.capabilities()
                .contains(&TechniqueCapability::ByteTransform)
                && detections.is_detected(tech.id())
                && !detections.is_transformed(tech.id())
        })
        .collect();
    let failed_byte_transforms: BTreeSet<&str> = failed.iter().map(|tech| tech.id()).collect();

    let mut request = detections.merged_cleanup_excluding(&failed_byte_transforms);

    for tech in &failed {
        log::warn!(
            "Withholding cleanup for {}: it declares a byte transform that did not succeed, \
             so the metadata it would delete is still in use",
            tech.id()
        );

        // Whatever the technique was meant to restore is still in its protected
        // form. Such a method carries no calls, so nothing it references looks
        // reachable - see the suppression of type-level deletion below - and it
        // is itself real code that must survive for later analysis.
        let Some(detection) = detections.get(tech.id()) else {
            continue;
        };
        let unrecovered = tech.unrecovered_methods(detection);
        if !unrecovered.is_empty() {
            log::warn!(
                "Protecting {} method(s) {} could not restore",
                unrecovered.len(),
                tech.id()
            );
            request.protect_tokens(unrecovered);
        }
    }

    let still_called = decryptors_still_called(ctx, ssa_call_graph);
    for tech in registry.sorted_techniques(detections) {
        if !detections.is_detected(tech.id()) {
            continue;
        }
        let Some(detection) = detections.get(tech.id()) else {
            continue;
        };
        if let Some(tech_cleanup) = tech.cleanup(detection) {
            // A technique builds its cleanup request from detection findings
            // alone - it cannot see whether the transformation it implies
            // actually succeeded. Merging it unconditionally deletes the
            // decryptor, its owning infrastructure type and the encrypted data
            // even when not a single call site was reversed, leaving live call
            // sites pointing at methods that no longer exist. Withhold the whole
            // request when a decryptor it removes is still called: deleting what
            // was never replaced is strictly worse than leaving the obfuscation
            // in place.
            let unreversed: Vec<Token> = tech_cleanup
                .methods()
                .filter(|t| still_called.contains(t))
                .copied()
                .collect();
            if unreversed.is_empty() {
                request.merge(&tech_cleanup);
            } else {
                log::warn!(
                    "Skipping cleanup for {}: {} decryptor(s) still have live call sites \
                     ({} decryption failures); their infrastructure must survive",
                    tech.id(),
                    unreversed.len(),
                    ctx.decryptors.total_failed(),
                );
            }
        }
    }

    // Protect decryptors that anything still calls, and remove the rest.
    // A successful decryption rewrites its call site to the decrypted constant,
    // so a decryptor with no remaining callers has been fully reversed and is
    // safe to delete. One that is still called has not been - deleting it would
    // leave those call sites referencing a method that no longer exists.
    for token in ctx.decryptors.registered_tokens() {
        if still_called.contains(&token) {
            request.protect_token(token);
        } else {
            request.add_method(token);
        }
    }

    // Pre-scan: mark <Module> methods as dead if they have no live callers.
    sweep_dead_module_methods(assembly, &mut request, ssa_call_graph, ctx);

    // Mark orphaned proxy forwarding stubs as devirtualized. These are mild
    // proxy stubs that were only called from infrastructure code (e.g., .cctor)
    // that was subsequently neutralized. The neutralization removed the calls
    // but didn't use mark_inlined, so the stubs have zero callers in the SSA
    // call graph but was_inlined is false. Detecting the proxy pattern confirms
    // they're trivial forwarding stubs, safe to delete.
    mark_orphaned_proxy_stubs(assembly, &request, ssa_call_graph, ctx);

    // Sweep for inlined/devirtualized proxy methods in ALL types.
    sweep_inlined_unreferenced_methods(assembly, &mut request, ssa_call_graph, ctx);

    // Find and add unreferenced infrastructure types via call graph analysis.
    // This uses cluster analysis: candidate types that only reference each
    // other (and already-deleted entities) are detected as isolated
    // infrastructure and removed.
    //
    // Skipped entirely when a byte transform failed. The analysis decides a type
    // is unreferenced by asking the call graph who names it, and a method whose
    // body is still encrypted contributes no edges at all - neither the SSA
    // graph, which never converted it, nor the static graph, which was built
    // from the same stub. Almost every non-public type then looks unrooted and
    // the assembly is gutted rather than cleaned. Protection cannot save it
    // either: this analysis does not consult the protected set, and deleting a
    // type takes its members with it.
    if failed_byte_transforms.is_empty() {
        let unreferenced_types = find_unreferenced_types(assembly, ssa_call_graph, &request);
        for type_token in unreferenced_types {
            request.add_type(type_token);
        }
    } else {
        log::warn!(
            "Skipping unreferenced-type removal: {} byte transform(s) failed, so the call \
             graph cannot distinguish unreachable from undecrypted",
            failed_byte_transforms.len()
        );
    }

    // Add dead methods from analysis (aggressive mode only)
    let aggressive = ctx.config.cleanup.remove_unused_methods;
    if aggressive {
        let entry_points = compute_entry_points(assembly, aggressive);
        for token in ctx.dead_methods.iter() {
            let token = *token;
            if !entry_points.contains(&token) {
                request.add_method(token);
            }
        }
    }

    // Remove types whose methods are ALL dead or devirtualized.
    remove_dispensable_types(assembly, &mut request, ctx);

    // Add tokens neutralized by SSA passes as cascade candidates.
    if ctx.config.cleanup.remove_orphan_metadata {
        let neutralized = ctx.neutralized_tokens.iter().map(|t| *t);
        request.add_rewrite_orphaned_tokens(neutralized);
    }

    // Detect empty module methods and add to cleanup request.
    sweep_empty_module_cctor(assembly, &mut request, ctx);

    // Rows whose removal repairs an ECMA-335 violation are proposed here, so that the
    // retraction below keeps those surviving code still names; the repair renames or
    // otherwise repairs what is kept.
    repairs::propose_removals(assembly, &mut request);

    // Last, and over everything the producers above decided: withdraw whatever
    // surviving code still names.
    retract_referenced_removals(
        assembly,
        &mut request,
        ssa_call_graph,
        ctx,
        &BTreeSet::new(),
    );

    request
}

/// Maps every method and field token to the type that declares it.
fn build_member_owner_map(assembly: &CilObject) -> HashMap<Token, Token> {
    let mut owner = HashMap::new();
    for type_entry in assembly.types().iter() {
        let type_token = *type_entry.key();
        if !type_token.is_table(TableId::TypeDef) {
            continue;
        }
        let cil_type = type_entry.value();
        for method in cil_type.methods() {
            owner.insert(method.token, type_token);
        }
        for (_, field) in cil_type.fields.iter() {
            owner.insert(field.token, type_token);
        }
    }
    owner
}

/// Every token that code surviving this request still names.
///
/// A converted method answers for itself: [`referenced_token`] is the same
/// question neutralization asks of each instruction, so the two agree by
/// construction rather than by a rule written twice. A method that ships its
/// original body - one that never converted (an encrypted body, a native one,
/// one that failed to decode) or whose regenerated code was refused - answers
/// by that body: every token its IL names, and through the static call graph
/// what it calls.
///
/// [`referenced_token`]: crate::analysis::SsaOpCilExt::referenced_token
fn tokens_named_by_survivors(
    assembly: &CilObject,
    removed: &HashSet<Token>,
    request: &CleanupRequest,
    ssa_call_graph: &BTreeMap<Token, BTreeSet<Token>>,
    ctx: &AnalysisContext,
    kept_original: &BTreeSet<Token>,
) -> BTreeSet<Token> {
    let mut named = BTreeSet::new();

    // A token names a row of this assembly, and through a MemberRef or MethodSpec the method
    // or field of this assembly it stands for: a generic method's instantiation, a member of
    // a generic type.
    let resolver = assembly.resolver();
    let naming = |token: Token| {
        std::iter::once(token)
            .chain(resolver.resolve_method(token))
            .chain(resolver.resolve_field(token))
    };

    // A converted method's call to a protection method is what neutralization
    // strips, so it does not keep the method. A method that never converted
    // cannot be rewritten, and still does.
    for entry in ctx.ssa_functions.iter() {
        if removed.contains(entry.key()) || kept_original.contains(entry.key()) {
            continue;
        }
        for (_, _, instr) in entry.value().iter_instructions() {
            if let Some(token) = instr.op().referenced_token() {
                for token in naming(token) {
                    if removed.contains(&token) && !request.strips_call_sites(token) {
                        named.insert(token);
                    }
                }
            }
        }
    }

    let ships_original =
        |method: &Token| kept_original.contains(method) || !ctx.ssa_functions.contains_key(method);
    for (caller, callees) in ssa_call_graph {
        if removed.contains(caller) || !ships_original(caller) {
            continue;
        }
        for callee in callees {
            if removed.contains(callee) {
                named.insert(*callee);
            }
        }
    }

    // The original body names more than its calls: the fields it loads, the
    // types it casts to, the generic methods its MethodSpecs instantiate.
    for entry in assembly.methods().iter() {
        let method = *entry.key();
        if removed.contains(&method) || !ships_original(&method) {
            continue;
        }
        let Some(blocks) = entry.value().blocks.get() else {
            continue;
        };
        for instr in blocks.iter().flat_map(|block| block.instructions.iter()) {
            let Operand::Token(token) = instr.operand else {
                continue;
            };
            for token in naming(token) {
                if removed.contains(&token) {
                    named.insert(token);
                }
            }
        }
    }

    named
}

/// The virtual methods of surviving types that the request removes.
///
/// A virtual method is reached through a slot, not by name: callers dispatch
/// through the base method or the interface, and no call names the override.
/// So a call graph shows it without callers, and removing it strips the slot
/// its type fills - a concrete type left with an abstract slot, or a derived
/// type silently falling back to its base's behaviour. The runtime refuses the
/// first ("invalid vtable method slot"); the second changes what the program
/// does. While its type survives, the method's slot names it.
fn slots_of_survivors(
    assembly: &CilObject,
    removed: &HashSet<Token>,
    owner_of: &HashMap<Token, Token>,
) -> Vec<Token> {
    removed
        .iter()
        .filter(|token| token.is_table(TableId::MethodDef))
        .filter(|token| {
            owner_of
                .get(token)
                .is_some_and(|owner| !removed.contains(owner))
        })
        .filter(|token| {
            assembly
                .methods()
                .get(token)
                .is_some_and(|entry| entry.value().is_virtual())
        })
        .copied()
        .collect()
}

/// Records the types each method's local variables are declared with.
///
/// A regenerated body declares a local for each variable its code still defines
/// or reads, of the variable's type or, for one of the method's own locals, its
/// original declaration. A variable the passes left without a definition or a
/// read declares nothing: the SSA keeps it until canonicalization, and a type
/// only such variables carry (a protection's state the decryption removed) is
/// named by nothing. A body that never converted keeps the signature it was
/// read with.
fn add_local_type_names(assembly: &CilObject, ctx: &AnalysisContext, names: &mut TypeNames) {
    for entry in assembly.methods().iter() {
        let token = *entry.key();
        if let Some(ssa) = ctx.ssa_functions.get(&token) {
            let live: HashSet<SsaVarId> = ssa
                .blocks()
                .iter()
                .flat_map(|block| block.defined_variables().chain(block.used_variables()))
                .collect();
            let original = ssa.original_local_types().unwrap_or_default();
            for var in ssa.variables() {
                if !live.contains(&var.id()) {
                    continue;
                }
                names.add_signature(Some(token), &var.var_type().to_type_signature());
                if let VariableOrigin::Local(idx) = var.origin() {
                    if let Some(local) = original.get(usize::from(idx)) {
                        names.add_signature(Some(token), &local.base);
                    }
                }
            }
        } else {
            let method = entry.value();
            let locals = TypeContext::new(method, assembly).local_type_signatures();
            for local in locals.unwrap_or_default() {
                names.add_signature(Some(token), &local.base);
            }
        }
    }
}

/// Withdraws every removal that surviving code still names.
///
/// Each producer above decides in isolation, from the snapshot of deletions
/// that existed when it ran, and none of them sees the finished request. They
/// also disagree about what makes a method dead: three consult the call graph
/// for live callers, `remove_dispensable_types` asks only whether proxy
/// devirtualization ever inlined the method - which it records after inlining
/// a single call site, not the last one.
///
/// The property that has to hold is not any one producer's, and it is what both
/// consumers of the request depend on: **no surviving code names a token the
/// request removes**. Cleanup deletes the row and leaves the surviving body
/// pointing at nothing. Neutralization reads the same request and NOPs every
/// instruction that names it, which for a proxy the method forwards all of its
/// calls through is the entire method body.
///
/// So this runs last and retracts, in a fixpoint: withdrawing a type resurrects
/// its methods, and their bodies name tokens of their own that no producer had
/// to account for while the type was going away.
///
/// `kept_original` names converted methods that ship their original body
/// anyway, because their regenerated code was refused: their IL answers for
/// them, as it does for a method that never converted. The engine runs this
/// again after code generation with that set.
pub(crate) fn retract_referenced_removals(
    assembly: &CilObject,
    request: &mut CleanupRequest,
    ssa_call_graph: &BTreeMap<Token, BTreeSet<Token>>,
    ctx: &AnalysisContext,
    kept_original: &BTreeSet<Token>,
) {
    let owner_of = build_member_owner_map(assembly);
    // What names which type does not change while this runs; only which of
    // the naming rows survive does.
    let mut names = TypeNames::of_metadata(assembly);
    add_local_type_names(assembly, ctx, &mut names);

    loop {
        let removed = expand_type_tokens(request, assembly);
        if removed.is_empty() {
            return;
        }

        // Surviving metadata names types without any instruction mentioning
        // them: signatures, base types, interfaces, locals. Which rows survive
        // is asked again each round, because a withdrawn type brings its
        // members back.
        let mut named = tokens_named_by_survivors(
            assembly,
            &removed,
            request,
            ssa_call_graph,
            ctx,
            kept_original,
        );
        named.extend(
            names
                .named_by_survivors(&removed)
                .filter(|t| removed.contains(t)),
        );
        named.extend(slots_of_survivors(assembly, &removed, &owner_of));
        if named.is_empty() {
            return;
        }

        // A token is in the removal set either on its own account or because
        // its declaring type is going; withdrawing the member alone would not
        // save it in the second case.
        let mut withdrawn = 0usize;
        for token in named {
            let directly = request.withdraw(token);
            let by_owner = owner_of
                .get(&token)
                .copied()
                .is_some_and(|owner| request.withdraw(owner));
            if directly || by_owner {
                withdrawn = withdrawn.saturating_add(1);
                log::warn!(
                    "Keeping {} ({}): surviving code or metadata still names it",
                    token,
                    assembly
                        .resolve_method_name(token)
                        .unwrap_or_else(|| "non-method".to_string()),
                );
            }
        }

        // Nothing left to retract means the remaining references are to tokens
        // the request does not own - an orphan cascade decision, not one made
        // here - and another round would not change the set.
        if withdrawn == 0 {
            return;
        }
    }
}

/// Executes cleanup with a complete request.
///
/// The request is expected to arrive complete (built by [`build_cleanup_request`]).
/// This function applies renames if enabled, repairs metadata anomalies, logs
/// deletions, and delegates to the cilassembly executor.
///
/// # Arguments
///
/// * `assembly` - The assembly to clean up (consumed and regenerated).
/// * `cleanup_request` - Optional complete cleanup request. If `None`, a default
///   request is created from the analysis context configuration.
/// * `ctx` - The analysis context containing configuration and event log.
///
/// # Returns
///
/// A new `CilObject` with the requested cleanup applied and names renamed.
///
/// # Errors
///
/// Returns an error if string heap updates fail during renaming, or if
/// regeneration of the cleaned assembly fails.
pub fn execute_cleanup(
    assembly: CilObject,
    cleanup_request: Option<CleanupRequest>,
    ctx: &AnalysisContext,
) -> Result<CilObject> {
    let request = cleanup_request.unwrap_or_else(|| {
        CleanupRequest::with_settings(
            ctx.config.cleanup.remove_orphan_metadata,
            ctx.config.cleanup.remove_empty_types,
        )
    });

    // Determine if we should rename obfuscated names
    let rename_obfuscated = ctx.config.cleanup.rename_obfuscated_names;

    // Nothing to do.
    //
    // Metadata repairs (`repairs::REPAIRS`) must run even when the request is
    // empty - some samples (notably .NET Reactor's SuppressIldasm) have no
    // technique-driven deletions but still carry ECMA-335 violations that
    // break strict-mode reload. `repairs::needs_repair` short-circuits the
    // exit when any of those violations are present.
    if !request.has_deletions()
        && request.excluded_sections().is_empty()
        && !rename_obfuscated
        && !repairs::needs_repair(&assembly)
    {
        return Ok(assembly);
    }

    // Log what we're cleaning
    let types_count = request.types_len();
    let methods_count = request.methods_len();
    let fields_count = request.fields_len();

    if types_count > 0 || methods_count > 0 || fields_count > 0 {
        log::info!("Cleanup: {types_count} types, {methods_count} methods, {fields_count} fields");
        // Counts alone cannot answer "why is this still here" or "what took that away",
        // which is the question any cleanup investigation starts from.
        if log::log_enabled!(log::Level::Debug) {
            let fmt = |it: &mut dyn Iterator<Item = &Token>| {
                it.map(|t| format!("0x{:08x}", t.value()))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            log::debug!("Cleanup types:   {}", fmt(&mut request.types()));
            log::debug!("Cleanup methods: {}", fmt(&mut request.methods()));
        }
    }

    for section_name in request.excluded_sections() {
        ctx.events
            .record(EventKind::ArtifactRemoved)
            .message(format!("Removing artifact section: {section_name}"));
    }

    // Log individual removals before consuming the assembly
    log_cleanup_request(&request, &assembly, ctx);

    // Collect rename entries while CilObject is still alive (before consumption).
    // The smart renamer needs CilObject-level APIs (types(), resolver(), member_ref())
    // for metadata queries - these aren't available on CilAssembly.
    let rename_entries = if rename_obfuscated {
        Some(renamer::renames_collect(
            &assembly,
            ctx.config.cleanup.smart_rename.as_ref(),
        )?)
    } else {
        None
    };

    // Convert directly - no reparsing needed (consumes CilObject)
    let mut cil_assembly = assembly.into_assembly();

    // Clone excluded sections before moving request
    let excluded_sections: HashSet<String> = request.excluded_sections().clone();

    // Repair the ECMA-335 violations obfuscators plant in metadata; a repair may hand rows
    // to the cleanup executor through the request.
    let mut request = request;
    repairs::apply_repairs(&mut cil_assembly, &mut request, ctx);

    // Add cleanup request (the actual cleanup is executed during generation)
    cil_assembly.add_cleanup(&request);

    // Apply collected renames to the string heap
    if let Some(entries) = rename_entries {
        let count = renamer::renames_apply(&mut cil_assembly, entries)?;
        if count > 0 {
            ctx.events
                .record(EventKind::ArtifactRemoved)
                .message(format!(
                    "Renamed {count} obfuscated names to simple identifiers"
                ));
        }
    }

    // Regenerate with excluded sections
    // The cleanup is automatically executed during into_cilobject_with
    let generator_config = GeneratorConfig::default().with_excluded_sections(excluded_sections);
    cil_assembly.into_cilobject_with(ValidationConfig::analysis(), generator_config)
}

/// Logs cleanup request details to the event log.
///
/// Records an [`EventKind::ArtifactRemoved`] event for each type, method,
/// field, and custom attribute scheduled for removal. Type events include
/// the fully-qualified name when available; methods and fields log their
/// token values.
fn log_cleanup_request(request: &CleanupRequest, assembly: &CilObject, ctx: &AnalysisContext) {
    // Log type removals
    for type_token in request.types() {
        if let Some(cil_type) = assembly.types().get(type_token) {
            ctx.events
                .record(EventKind::ArtifactRemoved)
                .message(format!(
                    "Removing type: {} (0x{:08X})",
                    cil_type.name,
                    type_token.value()
                ));
        } else {
            ctx.events
                .record(EventKind::ArtifactRemoved)
                .message(format!("Removing type: TypeDef RID {}", type_token.row()));
        }
    }

    // Log method removals, saying when the method goes because every call to it was inlined:
    // that is a method of the program, not of the protection
    for method_token in request.methods() {
        ctx.events
            .record(EventKind::ArtifactRemoved)
            .method(*method_token)
            .message(if ctx.was_inlined(*method_token) {
                INLINED_METHOD_REMOVED
            } else {
                "Removing method"
            });
    }

    // Log field removals
    for field_token in request.fields() {
        ctx.events
            .record(EventKind::ArtifactRemoved)
            .message(format!("Removing field 0x{:08X}", field_token.value()));
    }

    // Log attribute removals
    for attr_token in request.attributes() {
        ctx.events
            .record(EventKind::ArtifactRemoved)
            .message(format!(
                "Removing custom attribute 0x{:08X}",
                attr_token.value()
            ));
    }
}

/// Sweeps dead `<Module>` methods via reverse call graph analysis.
///
/// After techniques tag their decryptor/initializer methods for deletion,
/// other `<Module>` helper methods (LZMA decompression, etc.) may have no
/// remaining callers. This checks the SSA call graph and treats a method
/// as dead if every caller is already tagged for deletion.
///
/// Runs in a fixpoint loop to handle transitive chains (e.g., `.cctor` →
/// `Initialize` → LZMA helper).
fn sweep_dead_module_methods(
    assembly: &CilObject,
    request: &mut CleanupRequest,
    ssa_call_graph: &BTreeMap<Token, BTreeSet<Token>>,
    ctx: &AnalysisContext,
) {
    let Some(module_type) = assembly.types().module_type() else {
        return;
    };

    let mut deleted_methods: HashSet<Token> = request.methods().copied().collect();
    let deleted_types: HashSet<Token> = request.types().copied().collect();

    // Expand deleted types to include their method tokens
    let type_registry = assembly.types();
    for type_token in &deleted_types {
        if let Some(cil_type) = type_registry.get(type_token) {
            for m in cil_type.methods() {
                deleted_methods.insert(m.token);
            }
        }
    }

    // Build reverse call graph: callee → set of callers
    let mut callers_of: HashMap<Token, HashSet<Token>> = HashMap::new();
    for (caller, callees) in ssa_call_graph {
        for callee in callees {
            callers_of.entry(*callee).or_default().insert(*caller);
        }
    }

    // Fixpoint: each round may reveal methods whose callers are now all dead
    loop {
        let mut newly_dead = Vec::new();
        for method in module_type.methods() {
            if deleted_methods.contains(&method.token) {
                continue;
            }
            let callers = callers_of.get(&method.token);
            let has_callers = callers.is_some_and(|c| !c.is_empty());
            // A method is dead if it has known callers and ALL of them are deleted.
            let all_callers_deleted = callers.is_some_and(|c| {
                !c.is_empty() && c.iter().all(|caller| deleted_methods.contains(caller))
            });

            // Methods with NO callers in the SSA graph are conservatively kept -
            // the SSA call graph only covers successfully-converted methods, so
            // "no callers" may mean the caller wasn't converted to SSA.
            // Exception: if the method was inlined by the proxy devirtualization
            // pass, "no callers" means ALL call sites were replaced with direct
            // calls - the method is truly dead, not just missing from the graph.
            let inlined_and_unreferenced = !has_callers && ctx.was_inlined(method.token);

            if method.is_cctor() {
                // .cctor is invoked by the runtime, not via IL - it has
                // no callers. Instead check callees: if ALL its callees
                // are already deleted, the .cctor is pure infrastructure.
                if let Some(callees) = ssa_call_graph.get(&method.token) {
                    if !callees.is_empty() && callees.iter().all(|c| deleted_methods.contains(c)) {
                        newly_dead.push(method.token);
                    }
                }
            } else if all_callers_deleted || inlined_and_unreferenced {
                newly_dead.push(method.token);
            }
        }
        if newly_dead.is_empty() {
            break;
        }
        for token in &newly_dead {
            deleted_methods.insert(*token);
            request.add_method(*token);
        }
    }
}

/// Scans the assembly IL for mild proxy stubs and adds them to the cleanup request.
///
/// A mild proxy stub has IL pattern: `[ldarg*] call/callvirt <external> ret`.
/// The call target must be external (MemberRef to a non-local method) to avoid
/// false positives on methods that happen to forward to internal helpers.
///
/// This catches proxy stubs whose SSA-level detection failed because:
/// - CFF obfuscation was applied to larger proxy stubs (detected by CFF
///   unflattening but simplified too late for the proxy pass)
/// - The SSA was modified by passes that broke the proxy pattern
///
/// Marks orphaned proxy forwarding stubs as devirtualized.
///
/// After neutralization removes calls from infrastructure code (e.g., .cctor),
/// mild proxy stubs may have zero callers without `mark_inlined` being set
/// (neutralization NOPs calls, it doesn't use the proxy devirt path).
/// This function detects these orphaned stubs by checking the proxy forwarding
/// pattern on methods with SSA, zero callers, and no entry point status.
fn mark_orphaned_proxy_stubs(
    assembly: &CilObject,
    request: &CleanupRequest,
    ssa_call_graph: &BTreeMap<Token, BTreeSet<Token>>,
    ctx: &AnalysisContext,
) {
    let deleted_methods: HashSet<Token> = request.methods().copied().collect();

    // Build set of methods that have at least one live caller
    let mut has_caller: HashSet<Token> = HashSet::new();
    for (caller, callees) in ssa_call_graph {
        if deleted_methods.contains(caller) {
            continue;
        }
        for callee in callees {
            has_caller.insert(*callee);
        }
    }

    let entry_token = assembly.cor20header().entry_point_token;

    for entry in ctx.ssa_functions.iter() {
        let token = *entry.key();
        if token.table() != 0x06
            || deleted_methods.contains(&token)
            || has_caller.contains(&token)
            || ctx.was_inlined(token)
            || ctx.was_devirtualized(token)
            || token.value() == entry_token
        {
            continue;
        }

        // Skip constructors and static constructors
        if let Some(name) = assembly.resolve_method_name(token) {
            if name == ".ctor" || name == ".cctor" {
                continue;
            }
        }

        // Check if this is a proxy forwarding stub via live SSA pattern.
        let is_proxy = ctx
            .with_ssa(token, |ssa| {
                ProxyDevirtualizationPass::detect_proxy_pattern(ssa).is_some()
            })
            .unwrap_or(false);

        if is_proxy {
            ctx.mark_devirtualized(token);
        }
    }
}

/// Sweeps ALL types for methods that were inlined by the SSA proxy
/// devirtualization pass and have no remaining callers in the SSA call graph.
/// Unlike `sweep_dead_module_methods` (which only handles `<Module>`), this
/// catches proxy stubs that ConfuserEx injects into user types.
fn sweep_inlined_unreferenced_methods(
    assembly: &CilObject,
    request: &mut CleanupRequest,
    ssa_call_graph: &BTreeMap<Token, BTreeSet<Token>>,
    ctx: &AnalysisContext,
) {
    let deleted_methods: HashSet<Token> = request.methods().copied().collect();

    // Build reverse call graph: callee → set of live callers
    let mut callers_of: HashMap<Token, HashSet<Token>> = HashMap::new();
    for (caller, callees) in ssa_call_graph {
        if deleted_methods.contains(caller) {
            continue;
        }
        for callee in callees {
            callers_of.entry(*callee).or_default().insert(*caller);
        }
    }

    let registry = assembly.types();
    for type_entry in registry.iter() {
        let cil_type = type_entry.value();
        if cil_type.is_module_type() {
            continue; // Already handled by sweep_dead_module_methods
        }
        for method in cil_type.methods() {
            if deleted_methods.contains(&method.token) || method.is_cctor() || method.is_ctor() {
                continue;
            }
            let has_callers = callers_of.get(&method.token).is_some_and(|c| !c.is_empty());
            if has_callers {
                continue;
            }
            // A method with no callers in the post-SSA call graph is dead if:
            // - was_inlined: all direct call sites were devirtualized
            // - was_devirtualized: only reachable through deleted callers (e.g.,
            //   delegate targets of deleted strong proxy stubs)
            if ctx.was_inlined(method.token) || ctx.was_devirtualized(method.token) {
                request.add_method(method.token);
            }
        }
    }
}

/// Removes types whose methods are ALL dead or devirtualized.
///
/// After proxy devirtualization replaces calls to obfuscator wrapper methods,
/// the wrapper type's methods become unreferenced. If every method of a type
/// is either inlined (proxy devirt) or dead (global DCE), the type is
/// obfuscator infrastructure and should be deleted.
fn remove_dispensable_types(
    assembly: &CilObject,
    request: &mut CleanupRequest,
    ctx: &AnalysisContext,
) {
    let registry = assembly.types();
    for type_entry in registry.iter() {
        let token: Token = *type_entry.key();
        if token.table() != 0x02 {
            continue;
        }
        if request.types().any(|t| *t == token) {
            continue;
        }
        let cil_type = type_entry.value();
        let methods: Vec<_> = cil_type
            .methods()
            .map(|m| (m.token, m.is_cctor()))
            .collect();
        if methods.is_empty() {
            continue;
        }
        // A type is dispensable if every method is either:
        // - inlined (proxy devirtualization replaced all call sites)
        // - dead (global DCE found no callers)
        // - a .cctor (runtime-invoked, but only exists to initialize
        //   the above - dispensable when all other methods are gone)
        let all_dispensable = methods
            .iter()
            .all(|(m, is_cctor)| *is_cctor || ctx.was_inlined(*m) || ctx.is_dead(*m));
        // Require at least one non-cctor method to be dispensable
        // (avoids deleting types that only have a .cctor)
        let has_dispensable_methods = methods
            .iter()
            .any(|(m, is_cctor)| !is_cctor && (ctx.was_inlined(*m) || ctx.is_dead(*m)));
        if all_dispensable && has_dispensable_methods {
            request.add_type(token);
        }
    }
}

/// Sweeps empty `<Module>` methods after neutralization.
///
/// Scans all methods in `<Module>` that were processed by the SSA pipeline
/// and marks those with <= 1 instruction (just `ret`) for removal. This covers
/// the module `.cctor` (after anti-tamper/anti-debug removal) and other
/// infrastructure methods (anti-debug hooks, etc.) that become empty bodies
/// after the neutralization pass NOP'd their contents.
///
/// `.cctor` methods are always safe to delete when empty because they are
/// invoked by the runtime on first type access, not via explicit IL calls.
/// Non-`.cctor` methods are only deleted if they are known dead (not called
/// by any surviving method). This prevents deleting junk methods that are
/// still referenced - deleting them would shift RIDs and create dangling
/// call targets in the callers.
fn sweep_empty_module_cctor(
    assembly: &CilObject,
    request: &mut CleanupRequest,
    ctx: &AnalysisContext,
) {
    let Some(module_type) = assembly.types().module_type() else {
        return;
    };

    for (_, method_ref) in module_type.methods.iter() {
        let Some(method) = method_ref.upgrade() else {
            continue;
        };

        let Some(ssa_func) = ctx.ssa_functions.get(&method.token) else {
            continue;
        };

        if ssa_func.instruction_count() <= 1 {
            let is_cctor = method.name == wellknown::members::CCTOR;
            let is_dead = ctx.dead_methods.contains(&method.token);

            if !is_cctor && !is_dead {
                continue;
            }

            log::debug!(
                "Sweep: empty module method 0x{:08X} ({}) with {} instructions",
                method.token.value(),
                method.name,
                ssa_func.instruction_count()
            );
            request.add_method(method.token);
        }
    }
}

/// Creates a standard cleanup request from the analysis context configuration.
///
/// Returns `None` if cleanup is disabled. Otherwise returns a `CleanupRequest`
/// with orphan removal and empty type settings from the config.
///
/// # Arguments
///
/// * `ctx` - The analysis context whose cleanup configuration is inspected.
///
/// # Returns
///
/// `Some(CleanupRequest)` with settings derived from the config, or `None`
/// if all cleanup options are disabled.
pub(crate) fn create_cleanup_request(ctx: &AnalysisContext) -> Option<CleanupRequest> {
    let cleanup_config = &ctx.config.cleanup;
    if !cleanup_config.any_enabled() {
        return None;
    }

    Some(CleanupRequest::with_settings(
        cleanup_config.remove_orphan_metadata,
        cleanup_config.remove_empty_types,
    ))
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use super::*;
    use crate::{
        analysis::{CallGraph, SsaFunction, SsaOp, SsaVariable},
        cilassembly::CleanupRequest,
        deobfuscation::utils::{is_obfuscated_name, is_special_name},
        metadata::{signatures::TypeSignature, token::Token},
        testkit::helpers::{load_sample, test_assembly_arc},
    };

    /// A virtual method of `crafted_2` with a body, and the type declaring it,
    /// chosen so that nothing else in the sample names the type.
    fn an_override() -> (Token, Token) {
        let assembly = test_assembly_arc();
        let owner_of = build_member_owner_map(&assembly);
        let candidates: Vec<(Token, Token)> = assembly
            .methods()
            .iter()
            .map(|entry| entry.value().clone())
            .filter(|method| method.is_virtual() && !method.is_abstract())
            .filter_map(|method| {
                owner_of
                    .get(&method.token)
                    .map(|&owner| (method.token, owner))
            })
            .collect();
        let names = TypeNames::of_metadata(&assembly);
        candidates
            .into_iter()
            .find(|&(_, owner)| {
                let mut request = CleanupRequest::new();
                request.add_type(owner);
                let removed = expand_type_tokens(&request, &assembly);
                let named = names
                    .named_by_survivors(&removed)
                    .any(|named| named == owner);
                !named
            })
            .expect("the sample overrides a method in a type nothing else names")
    }

    #[test]
    fn a_surviving_type_keeps_the_methods_filling_its_slots() {
        let assembly = test_assembly_arc();
        let ctx = AnalysisContext::new(Arc::new(CallGraph::new()));
        let (method, _) = an_override();

        // Nothing calls it by name, which is how a removal pass sees any
        // override: callers dispatch through the slot.
        let mut request = CleanupRequest::new();
        request.add_method(method);
        retract_referenced_removals(
            &assembly,
            &mut request,
            &BTreeMap::new(),
            &ctx,
            &BTreeSet::new(),
        );

        assert!(
            !request.methods().any(|&token| token == method),
            "{method:?} left its type's slot empty"
        );
    }

    #[test]
    fn a_converted_caller_keeps_the_generic_method_its_method_spec_instantiates() {
        // ConfuserEx's type scrambler: SayHello calls `BuildMessage<string>` through a
        // MethodSpec, and names BuildMessage only through it.
        let assembly = load_sample("packers/confuserex/1.6.0/mkaring_typescramble.exe");
        let say_hello = Token::new(0x0600_0007);
        let build_message = Token::new(0x0600_0009);
        let ctx = AnalysisContext::new(Arc::new(CallGraph::new()));
        let ssa = assembly
            .method(&say_hello)
            .and_then(|method| method.ssa(&assembly))
            .expect("SayHello converts");
        ctx.ssa_functions.insert(say_hello, ssa);

        let mut request = CleanupRequest::new();
        request.add_method(build_message);
        retract_referenced_removals(
            &assembly,
            &mut request,
            &BTreeMap::new(),
            &ctx,
            &BTreeSet::new(),
        );

        assert!(
            !request.methods().any(|&token| token == build_message),
            "BuildMessage removed while SayHello calls it"
        );
    }

    #[test]
    fn a_converted_method_keeps_the_field_a_member_ref_names() {
        // WindowsBase reads fields of its own generic types through MemberRefs.
        let assembly = load_sample("WindowsBase.dll");
        let resolver = assembly.resolver();
        let (method, field) = assembly
            .methods()
            .iter()
            .find_map(|entry| {
                let method = entry.value();
                let field = method.instructions().find_map(|instr| {
                    instr
                        .get_token_operand()
                        .filter(|token| token.is_table(TableId::MemberRef))
                        .and_then(|token| resolver.resolve_field(token))
                })?;
                let ssa = method.ssa(&assembly).ok()?;
                Some(((method.token, ssa), field))
            })
            .expect("a method reading a local field through a MemberRef");
        let ctx = AnalysisContext::new(Arc::new(CallGraph::new()));
        ctx.ssa_functions.insert(method.0, method.1);

        let mut request = CleanupRequest::new();
        request.add_field(field);
        retract_referenced_removals(
            &assembly,
            &mut request,
            &BTreeMap::new(),
            &ctx,
            &BTreeSet::new(),
        );

        assert!(
            !request.fields().any(|&token| token == field),
            "{field} removed while {} reads it",
            method.0
        );
    }

    #[test]
    fn a_converted_method_names_the_local_types_its_code_still_uses() {
        // ConfuserEx's CFG-mode constants: methods keep their decryption state in a local of
        // a value type with `uint Next(byte, uint)`. Once the decryption removes every use of
        // that state, the regenerated body declares no such local, though the SSA still lists
        // the variables and the original declaration.
        let assembly = load_sample("packers/confuserex/1.6.0/mkaring_constants_cfg.exe");
        let context_type = assembly
            .types()
            .iter()
            .find(|entry| {
                entry.value().methods().any(|method| {
                    let signature = &method.signature;
                    signature.return_type.base == TypeSignature::U4
                        && signature.params.len() == 2
                        && signature.params[0].base == TypeSignature::U1
                        && signature.params[1].base == TypeSignature::U4
                })
            })
            .map(|entry| *entry.key())
            .expect("the CFG-mode state type");
        let names_context = |var: &SsaVariable| {
            let mut named = HashSet::new();
            var.var_type().to_type_signature().type_tokens(&mut named);
            named.contains(&context_type)
        };
        let (method, mut ssa) = assembly
            .methods()
            .iter()
            .filter(|entry| {
                entry.value().declaring_type_rc().map(|t| t.token) != Some(context_type)
            })
            .find_map(|entry| {
                let ssa = entry.value().ssa(&assembly).ok()?;
                ssa.variables()
                    .iter()
                    .any(names_context)
                    .then_some((*entry.key(), ssa))
            })
            .expect("a method keeping its decryption state in a local");
        let others: HashSet<Token> = assembly
            .methods()
            .iter()
            .map(|entry| *entry.key())
            .filter(|&token| token != method)
            .collect();
        let named_by_method = |ssa: SsaFunction| {
            let ctx = AnalysisContext::new(Arc::new(CallGraph::new()));
            ctx.ssa_functions.insert(method, ssa);
            let mut names = TypeNames::default();
            add_local_type_names(&assembly, &ctx, &mut names);
            let named = names
                .named_by_survivors(&others)
                .any(|named| named == context_type);
            named
        };
        assert!(named_by_method(ssa.clone()), "the state's local is in use");

        // What the decryption leaves: nothing defines or reads a value of the state's type
        let state: HashSet<SsaVarId> = ssa
            .variables()
            .iter()
            .filter(|var| names_context(var))
            .map(SsaVariable::id)
            .collect();
        for block_idx in 0..ssa.block_count() {
            let Some(block) = ssa.block_mut(block_idx) else {
                continue;
            };
            block
                .phi_nodes_mut()
                .retain(|phi| !state.contains(&phi.result()));
            for instr in block.instructions_mut() {
                let touches = instr.def().is_some_and(|def| state.contains(&def))
                    || instr.uses().iter().any(|used| state.contains(used));
                if touches {
                    instr.set_op(SsaOp::Nop);
                }
            }
        }
        assert!(
            !named_by_method(ssa),
            "a local nothing uses names {context_type:?}"
        );
    }

    #[test]
    fn a_removed_type_takes_its_overrides_with_it() {
        let assembly = test_assembly_arc();
        let ctx = AnalysisContext::new(Arc::new(CallGraph::new()));
        let (method, owner) = an_override();

        let mut request = CleanupRequest::new();
        request.add_type(owner);
        request.add_method(method);
        retract_referenced_removals(
            &assembly,
            &mut request,
            &BTreeMap::new(),
            &ctx,
            &BTreeSet::new(),
        );

        let removed = expand_type_tokens(&request, &assembly);
        assert!(removed.contains(&owner), "nothing names {owner:?}");
        assert!(
            removed.contains(&method),
            "{method:?} was kept although {owner:?} goes"
        );
    }

    #[test]
    fn test_cleanup_request_builder() {
        let mut request = CleanupRequest::new();
        request
            .add_type(Token::new(0x02000001))
            .add_method(Token::new(0x06000001))
            .add_field(Token::new(0x04000001));

        assert!(request.has_deletions());
        assert_eq!(request.types_len(), 1);
        assert_eq!(request.methods_len(), 1);
        assert_eq!(request.fields_len(), 1);
    }

    #[test]
    fn test_is_obfuscated_name() {
        assert!(!is_obfuscated_name("MyClass"));
        assert!(!is_obfuscated_name("Main"));
        assert!(is_obfuscated_name("\u{200B}test"));
        assert!(is_obfuscated_name("te\u{200D}st"));
    }

    #[test]
    fn test_is_obfuscated_name_spaces() {
        // BitMono FullRenamer produces space-containing names from word pools
        assert!(is_obfuscated_name(
            "Translate Start <FixedUpdate>b__4_0.get_Syntax"
        ));
        assert!(is_obfuscated_name(
            "get_Syntax get_AllowedCaller get_RebindActionMap"
        ));
        assert!(is_obfuscated_name("A B"));
        // Single words without spaces are not obfuscated
        assert!(!is_obfuscated_name("ValidName"));
        assert!(!is_obfuscated_name("get_Value"));
    }

    #[test]
    fn test_is_special_name() {
        assert!(is_special_name(".ctor"));
        assert!(is_special_name(".cctor"));
        assert!(is_special_name("<Module>"));
        assert!(is_special_name("get_Value"));
        assert!(!is_special_name("MyMethod"));
    }

    #[test]
    fn test_is_special_name_rejects_spaces() {
        // Space-containing names with get_/set_ prefixes should NOT be treated as special
        assert!(!is_special_name("get_Syntax get_AllowedCaller"));
        assert!(!is_special_name("set_Value some_other_word"));
        assert!(!is_special_name(".ctor with spaces"));
        assert!(!is_special_name("<Module> extra"));
        // But angle-bracket-wrapped CLR names with spaces are legitimate
        assert!(is_special_name("<Generic Parameter>"));
        assert!(is_special_name("<Generic Method Parameter>"));
        // Legitimate special names still work
        assert!(is_special_name("get_Value"));
        assert!(is_special_name("set_Item"));
        assert!(is_special_name("add_Click"));
        assert!(is_special_name("remove_Changed"));
    }
}

#[cfg(test)]
mod examples {
    use std::sync::Arc;

    use super::*;
    use crate::{
        analysis::CallGraph,
        compiler::DerivedStats,
        metadata::tables::{CustomAttributeRaw, TableId},
        testkit::fixture,
        CleanupRequest, Result,
    };

    fn attribute_count(assembly: &CilObject) -> u32 {
        assembly
            .tables()
            .map_or(0, |tables| tables.table_row_count(TableId::CustomAttribute))
    }

    /// Removing an assembly-level attribute: the output has one attribute fewer, and the event
    /// log the statistics derive from records the removal.
    #[test]
    fn module_example() -> Result<()> {
        let assembly = CilObject::from_path(fixture("packers/confuserex/1.6.0/original.exe"))?;
        let before = attribute_count(&assembly);
        let attribute = assembly
            .tables()
            .and_then(|tables| tables.table::<CustomAttributeRaw>())
            .and_then(|table| {
                table
                    .iter()
                    .filter_map(std::result::Result::ok)
                    .find(|row| row.parent.token.is_table(TableId::Assembly))
            })
            .expect("an assembly-level attribute")
            .token;
        let ctx = AnalysisContext::new(Arc::new(CallGraph::new()));

        let mut request = CleanupRequest::new();
        request.add_attribute(attribute);
        let assembly = execute_cleanup(assembly, Some(request), &ctx)?;

        assert_eq!(attribute_count(&assembly), before - 1);
        // Statistics are derived from the event log
        assert!(DerivedStats::from_log(&ctx.events).artifacts_removed >= 1);
        Ok(())
    }
}

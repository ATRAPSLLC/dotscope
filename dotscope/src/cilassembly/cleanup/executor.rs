//! Cleanup execution logic for applying cleanup requests.
//!
//! This module provides the main entry point for executing cleanup operations
//! on a [`CilAssembly`]. It coordinates the process of:
//!
//! 1. Deciding which requested types are deleted (closed over nesting, minus the types
//!    surviving code names and their enclosing types) and expanding those to their members
//! 2. Applying explicit deletions to the assembly changes
//! 3. Removing orphaned metadata entries
//!
//! The executor ensures deletions are applied in the correct order to maintain
//! referential integrity and avoid RID shifting issues.

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::{
    cilassembly::{
        cleanup::{
            compaction::mark_unreferenced_heap_entries,
            orphans::{self, DeletionContext},
            references::{
                collect_pre_deletion_references, collect_typedefs_from_field_signatures,
                collect_typedefs_from_typespec_signatures, scan_method_body_tokens,
            },
            utils::{is_cctor_method, try_remove},
            CleanupRequest, CleanupStats,
        },
        modifications::TableModifications,
        CilAssembly,
    },
    metadata::{
        tables::{
            skip_unreadable, CustomAttributeRaw, InterfaceImplRaw, MemberList, MethodImplRaw,
            MethodSemanticsRaw, MethodSpecRaw, NestedClassRaw, TableId, TypeDefRaw,
        },
        token::Token,
    },
    Result,
};

/// Executes cleanup operations on a [`CilAssembly`].
///
/// This is the main entry point for cleanup. It processes the [`CleanupRequest`],
/// applying all specified deletions and removing orphaned metadata.
///
/// # Process
///
/// 1. **Decide and expand types**: The requested types, closed over nesting, minus every
///    type the surviving methods name or that is protected (with its enclosing chain),
///    decided to a fixed point before any member is deleted. The methods and fields of the
///    types that go are collected for deletion; a requested type that stays keeps them.
///
/// 2. **Apply deletions**: Deletions are applied in order:
///    - Methods (sorted by RID descending)
///    - MethodSpecs (sorted by RID descending)
///    - Fields (sorted by RID descending)
///    - Types (sorted by RID descending)
///    - Attributes
///
/// 3. **Remove orphans**: If `remove_orphans` is enabled, cascading orphan
///    removal is performed for all related metadata tables.
///
/// # Arguments
///
/// * `assembly` - The assembly to modify
/// * `request` - The cleanup request specifying what to delete
///
/// # Returns
///
/// Statistics about what was removed.
///
/// # Example
///
/// The `examples::execute_cleanup_example` test in this module runs this example.
pub fn execute_cleanup(
    assembly: &mut CilAssembly,
    request: &CleanupRequest,
) -> Result<CleanupStats> {
    let mut stats = CleanupStats::new();

    if request.is_empty() {
        return Ok(stats);
    }

    // The rows deleted before cleanup, so the statistics count only what cleanup deletes
    let deleted_before = deleted_rows_by_table(assembly);

    // Phase 1: Decide which types go before any member goes with them, then expand those
    // types to their members. A requested type that surviving code still names stays, whole.
    let all_types = resolve_type_deletions(assembly, request);
    let (type_methods, type_fields) = expand_type_members(assembly, &all_types);

    // Combine explicit deletions with expanded members (using BTreeSet for sorted order)
    let mut all_methods: BTreeSet<Token> = request.methods().copied().collect();
    all_methods.extend(type_methods);

    let mut all_fields: BTreeSet<Token> = request.fields().copied().collect();
    all_fields.extend(type_fields);

    // Phase 1.5: Pre-deletion reference scan
    // Collect all tokens referenced by entities about to be deleted.
    // This must happen BEFORE deletion while method bodies and metadata
    // are still accessible. Used for cascade-based reference cleanup.
    let mut pre_refs =
        collect_pre_deletion_references(assembly, &all_methods, &all_fields, &all_types);

    // Merge rewrite-orphaned tokens (from SSA passes that neutralized calls)
    // into cascade candidates, so the existing cascade logic handles
    // MemberRef → TypeRef → AssemblyRef removal.
    pre_refs
        .il_tokens
        .extend(request.rewrite_orphaned_tokens().iter().copied());

    // Capture constructor tokens of explicitly-deleted CustomAttributes as
    // cascade candidates. These attributes may have Module as parent (not a
    // deleted type), so collect_pre_deletion_references won't capture them.
    {
        let view = assembly.view();
        if let Some(tables) = view.tables() {
            if let Some(attr_table) = tables.table::<CustomAttributeRaw>() {
                for attr_token in request.attributes() {
                    if let Some(attr) = attr_table.get(attr_token.row())? {
                        pre_refs.il_tokens.insert(attr.constructor.token);
                    }
                }
            }
        }
    }

    // Phase 2: Apply deletions in correct order
    // Track what was actually removed for deletion context
    let mut removed_types: HashSet<Token> = HashSet::new();
    let mut removed_methods: HashSet<Token> = HashSet::new();
    let mut removed_fields: HashSet<Token> = HashSet::new();

    // 2a: Remove methods (in descending RID order to avoid shifting issues)
    for method_token in all_methods.iter().rev() {
        if request.is_protected(*method_token) {
            continue;
        }
        if try_remove(assembly, TableId::MethodDef, method_token.row()) {
            removed_methods.insert(*method_token);
            stats.add(TableId::MethodDef, 1);
        }
    }

    // 2b: Remove MethodSpecs (in descending RID order)
    for spec_token in request.methodspecs() {
        if request.is_protected(*spec_token) {
            continue;
        }
        if try_remove(assembly, TableId::MethodSpec, spec_token.row()) {
            stats.add(TableId::MethodSpec, 1);
        }
    }

    // 2c: Remove fields (in descending RID order)
    for field_token in all_fields.iter().rev() {
        if request.is_protected(*field_token) {
            continue;
        }
        if try_remove(assembly, TableId::Field, field_token.row()) {
            removed_fields.insert(*field_token);
            stats.add(TableId::Field, 1);
        }
    }

    // 2d: Remove the types decided above (in descending RID order). The set is closed over
    // nesting, so no nested type outlives the type it is nested in, and keeps every type
    // surviving code names, with its enclosing chain.
    for type_token in all_types.iter().rev() {
        if try_remove(assembly, TableId::TypeDef, type_token.row()) {
            removed_types.insert(*type_token);
            stats.add(TableId::TypeDef, 1);
        }
    }

    // 2e: Remove explicit attributes (in descending RID order)
    for attr_token in request.attributes() {
        if try_remove(assembly, TableId::CustomAttribute, attr_token.row()) {
            stats.add(TableId::CustomAttribute, 1);
        }
    }

    // 2f: Remove AssemblyRefs (in descending RID order)
    for asmref_token in request.assemblyrefs() {
        if try_remove(assembly, TableId::AssemblyRef, asmref_token.row()) {
            stats.add(TableId::AssemblyRef, 1);
        }
    }

    // 2g: Remove ModuleRefs (in descending RID order)
    for modref_token in request.modulerefs() {
        if try_remove(assembly, TableId::ModuleRef, modref_token.row()) {
            stats.add(TableId::ModuleRef, 1);
        }
    }

    // 2h: Remove explicit ManifestResource rows (in descending RID order).
    //
    // This handles embedded resources whose payload lives in the PE's CLR
    // resource section. For rows with a non-zero `implementation` target,
    // this is still safe — the row is marked deleted and the generic
    // orphan sweep (`remove_orphan_manifestresources`) is a no-op for an
    // already-deleted row. Embedded payload bytes are dropped
    // automatically during PE regeneration: the writer's resource-section
    // compaction loop consults `is_row_deleted(TableId::ManifestResource, rid)`
    // and skips the entry, then rewrites `offset_field` on surviving rows
    // via `resource_offset_remap`.
    for res_token in request.manifest_resources() {
        if try_remove(assembly, TableId::ManifestResource, res_token.row()) {
            stats.add(TableId::ManifestResource, 1);
        }
    }

    // Phase 2.5: Dead definition elimination (unified fixpoint).
    //
    // After explicit deletions, methods and fields that were ONLY referenced
    // by the deleted entities become unreferenced. The cascade principle:
    // "if something was referenced by deleted entities and is no longer
    // referenced by any surviving entity, it is dead and should be removed."
    //
    // A MethodDef is considered "still alive" if it is referenced by ANY of:
    // - IL bytecode in a surviving method body (call, callvirt, newobj, etc.)
    // - MethodSpec.method (generic instantiation)
    // - CustomAttribute.constructor (attribute constructor)
    // - MethodSemantics.method (property getter/setter, event add/remove)
    // - MethodImpl.method_body or method_declaration (explicit overrides)
    //
    // A Field is considered "still alive" if it is referenced from any
    // surviving method's IL (ldfld, stfld, ldsfld, stsfld, ldflda, ldsflda).
    //
    // This is a fixpoint loop because each round of cascade-deleted definitions
    // may reveal further unreferenced definitions (transitive chains).
    if request.remove_orphans() {
        const MAX_CASCADE_ROUNDS: usize = 10;
        for _round in 0..MAX_CASCADE_ROUNDS {
            // Compute the full set of alive tokens from both IL bytecode
            // and all metadata tables that reference methods/fields.
            let alive_methods = collect_alive_method_tokens(assembly);
            let alive_fields = collect_alive_field_tokens(assembly);

            // Find MethodDef tokens from pre_refs that are no longer referenced
            // by any surviving entity.
            let dead_methods: Vec<Token> = pre_refs
                .il_tokens
                .iter()
                .filter(|t| t.is_table(TableId::MethodDef))
                .filter(|t| !alive_methods.contains(t))
                .filter(|t| !removed_methods.contains(t))
                .filter(|t| {
                    !assembly
                        .changes()
                        .is_row_deleted(TableId::MethodDef, t.row())
                })
                // Safety: never cascade-remove .cctor methods — they are
                // invoked by the runtime on first type access, not via IL.
                .filter(|t| !is_cctor_method(assembly, t.row()))
                .filter(|t| !request.is_protected(**t))
                .copied()
                .collect();

            // Find Field tokens from pre_refs that are no longer referenced
            // by any surviving entity. Only cascade-remove fields that appear
            // in pre_refs (were referenced by explicitly or previously deleted
            // entities) to avoid removing pre-existing unreferenced fields
            // that may be used via reflection.
            let dead_fields: Vec<Token> = pre_refs
                .il_tokens
                .iter()
                .filter(|t| t.is_table(TableId::Field))
                .filter(|t| !alive_fields.contains(t))
                .filter(|t| !removed_fields.contains(t))
                .filter(|t| !assembly.changes().is_row_deleted(TableId::Field, t.row()))
                .filter(|t| !request.is_protected(**t))
                .copied()
                .collect();

            if dead_methods.is_empty() && dead_fields.is_empty() {
                break;
            }

            // Collect pre-deletion refs from dead definitions BEFORE deleting
            // them, so their references feed into subsequent cascade rounds
            // and the MemberRef/TypeRef cascade.
            let dead_methods_set: BTreeSet<Token> = dead_methods.iter().copied().collect();
            let dead_fields_set: BTreeSet<Token> = dead_fields.iter().copied().collect();
            let empty_types = BTreeSet::new();
            let new_refs = collect_pre_deletion_references(
                assembly,
                &dead_methods_set,
                &dead_fields_set,
                &empty_types,
            );
            pre_refs.il_tokens.extend(new_refs.il_tokens);
            pre_refs.typeref_rids.extend(new_refs.typeref_rids);
            pre_refs
                .standalonesig_rids
                .extend(new_refs.standalonesig_rids);

            // Delete methods in reverse RID order to avoid shifting issues.
            let mut method_count = 0usize;
            for token in dead_methods.iter().rev() {
                if try_remove(assembly, TableId::MethodDef, token.row()) {
                    removed_methods.insert(*token);
                    method_count = method_count.saturating_add(1);
                }
            }
            stats.add(TableId::MethodDef, method_count);

            // Delete fields in reverse RID order.
            let mut field_count = 0usize;
            for token in dead_fields.iter().rev() {
                if try_remove(assembly, TableId::Field, token.row()) {
                    removed_fields.insert(*token);
                    field_count = field_count.saturating_add(1);
                }
            }
            stats.add(TableId::Field, field_count);
        }
    }

    // Rescan body tokens after MethodDef cascade — the set may have changed
    // significantly and both Phase 3 (empty types) and Phase 4 (reference
    // cascade) need an accurate snapshot.
    let body_tokens = scan_method_body_tokens(assembly, &HashSet::new());

    // Phase 3: Remove empty types (if enabled)
    // This MUST run before cascade reference cleanup (Phase 4) so that
    // TypeRef/AssemblyRef entries referenced only by empty types (e.g.,
    // System.ValueType for empty structs) are properly cascade-removed.
    if request.remove_empty_types() {
        let (empty_removed, empty_type_tokens) =
            remove_empty_types(assembly, &body_tokens, request);
        stats.add(TableId::TypeDef, empty_removed);

        if !empty_type_tokens.is_empty() {
            // Track empty type deletions for deletion context
            removed_types.extend(empty_type_tokens.iter().copied());

            let empty_methods = HashSet::new();
            let empty_fields = HashSet::new();
            let empty_ctx = DeletionContext::new(&empty_type_tokens, &empty_methods, &empty_fields);
            let type_dep_stats = orphans::remove_type_dependents(assembly, &empty_ctx);
            stats.merge(&type_dep_stats);
        }
    }

    // Phase 4: Remove dependent metadata and cascade references (if enabled)
    if request.remove_orphans() {
        let ctx = DeletionContext::new(&removed_types, &removed_methods, &removed_fields);
        let orphan_stats =
            orphans::remove_parent_child_dependents(assembly, &ctx, &pre_refs, &body_tokens);
        stats.merge(&orphan_stats);

        let cascade_stats = orphans::cascade_reference_cleanup(assembly, &pre_refs, &body_tokens);
        stats.merge(&cascade_stats);
    }

    // Phase 5: Compact heaps (mark the #Strings, #Blob and #GUID entries nothing references
    // for removal; see compaction.rs for what counts as referenced)
    let compaction_stats = mark_unreferenced_heap_entries(assembly)?;
    stats.blobs_compacted = compaction_stats.blobs;
    stats.guids_compacted = compaction_stats.guids;
    stats.strings_compacted = compaction_stats.strings;

    // Track excluded sections count
    stats.sections_excluded = request.excluded_sections().len();

    // Several passes may delete the same row (an explicitly requested type is also empty, or
    // nested in another deleted type); each row counts once.
    let mut removals = deleted_rows_by_table(assembly);
    for (table, count) in &mut removals {
        *count = count.saturating_sub(deleted_before.get(table).copied().unwrap_or(0));
    }
    removals.retain(|_, count| *count > 0);
    stats.set_removals(removals);

    Ok(stats)
}

/// The number of rows the pending changes delete, per table.
fn deleted_rows_by_table(assembly: &CilAssembly) -> HashMap<TableId, usize> {
    assembly
        .changes()
        .table_changes
        .iter()
        .filter_map(|(table, modifications)| match modifications {
            TableModifications::Sparse { deleted_rows, .. } => Some((*table, deleted_rows.len())),
            TableModifications::Replaced(_) => None,
        })
        .collect()
}

/// The TypeDefs a cleanup request deletes, decided before any member is deleted.
///
/// Starts from the requested types that are not protected and closes them over nesting: a
/// nested type cannot outlive its enclosing type (ECMA-335 II.22.32), at any depth. From
/// that set it removes every type that must stay, with its enclosing chain:
///
/// - a protected type, so a protected nested type keeps the type it is nested in;
/// - a type the bodies of the surviving methods name (IL operands, local and `calli`
///   signatures), whether requested or only nested in a requested type.
///
/// Which methods survive depends on which types go, and a type that stays keeps its methods,
/// whose bodies can name further types: the decision runs to a fixed point. The kept set only
/// grows, so it terminates. A requested type that stays therefore stays whole, members
/// included, instead of being emptied first and kept as a shell its callers no longer match.
///
/// # Arguments
///
/// * `assembly` - The assembly the request applies to
/// * `request` - The cleanup request
///
/// # Returns
///
/// The TypeDef tokens to delete.
fn resolve_type_deletions(assembly: &CilAssembly, request: &CleanupRequest) -> BTreeSet<Token> {
    let nested_of: HashMap<u32, Vec<u32>> = {
        let view = assembly.view();
        let mut nested_of: HashMap<u32, Vec<u32>> = HashMap::new();
        if let Some(nested_table) = view
            .tables()
            .and_then(|tables| tables.table::<NestedClassRaw>())
        {
            for nested in nested_table.iter().filter_map(skip_unreadable) {
                nested_of
                    .entry(nested.enclosing_class)
                    .or_default()
                    .push(nested.nested_class);
            }
        }
        nested_of
    };
    let typedef = |rid| Token::from_parts(TableId::TypeDef, rid);
    let explicit_methods: HashSet<Token> = request
        .methods()
        .copied()
        .filter(|token| !request.is_protected(*token))
        .collect();

    let mut kept: HashSet<u32> = HashSet::new();
    loop {
        // The requested types and everything nested in them, short of what must stay
        // (a protected type met on the way stays, and keeps the types it is nested in)
        let mut doomed: BTreeSet<u32> = BTreeSet::new();
        let mut protected: HashSet<u32> = HashSet::new();
        let mut worklist: Vec<u32> = request.types().map(Token::row).collect();
        while let Some(rid) = worklist.pop() {
            if request.is_protected(typedef(rid)) {
                protected.insert(rid);
                continue;
            }
            if kept.contains(&rid) || !doomed.insert(rid) {
                continue;
            }
            worklist.extend(nested_of.get(&rid).into_iter().flatten().copied());
        }
        let doomed_types: BTreeSet<Token> = doomed.iter().map(|rid| typedef(*rid)).collect();

        // What the methods that survive this decision name
        let (doomed_methods, _) = expand_type_members(assembly, &doomed_types);
        let mut gone = explicit_methods.clone();
        gone.extend(
            doomed_methods
                .into_iter()
                .filter(|token| !request.is_protected(*token)),
        );
        let mut must_stay: HashSet<u32> = scan_method_body_tokens(assembly, &gone)
            .iter()
            .filter(|token| token.is_table(TableId::TypeDef))
            .map(|token| token.row())
            .filter(|rid| doomed.contains(rid))
            .collect();
        must_stay.extend(protected);
        let must_stay = expand_with_enclosing_types(assembly, must_stay);

        if must_stay.iter().all(|rid| kept.contains(rid)) {
            return doomed_types;
        }
        kept.extend(must_stay);
    }
}

/// Adds the transitive enclosing chain of every nested type in `rids`.
///
/// Nesting is transitive, so the walk runs to a fixed point: a type nested two levels deep
/// keeps both of its ancestors alive, not just its immediate parent.
///
/// # Arguments
///
/// * `assembly` - The assembly to read the `NestedClass` table from
/// * `rids` - TypeDef RIDs that must survive
///
/// # Returns
///
/// `rids` plus every TypeDef RID that encloses one of them.
fn expand_with_enclosing_types(assembly: &CilAssembly, mut rids: HashSet<u32>) -> HashSet<u32> {
    let view = assembly.view();
    let Some(tables) = view.tables() else {
        return rids;
    };
    let Some(nested_table) = tables.table::<NestedClassRaw>() else {
        return rids;
    };

    let mut enclosing_of: HashMap<u32, u32> = HashMap::new();
    for nested in nested_table.iter().filter_map(skip_unreadable) {
        enclosing_of.insert(nested.nested_class, nested.enclosing_class);
    }

    let mut worklist: Vec<u32> = rids.iter().copied().collect();
    while let Some(rid) = worklist.pop() {
        if let Some(&enclosing) = enclosing_of.get(&rid) {
            if rids.insert(enclosing) {
                worklist.push(enclosing);
            }
        }
    }

    rids
}

/// Expands type deletions to include all their members.
///
/// For each type to be deleted, collects all its methods and fields so they can be
/// deleted along with the type.
///
/// # Arguments
///
/// * `assembly` - The assembly to read type information from
/// * `types` - The TypeDefs to be deleted
///
/// # Returns
///
/// A tuple of (methods_to_delete, fields_to_delete) tokens.
fn expand_type_members(
    assembly: &CilAssembly,
    types: &BTreeSet<Token>,
) -> (HashSet<Token>, HashSet<Token>) {
    let mut methods = HashSet::new();
    let mut fields = HashSet::new();

    let view = assembly.view();
    let Some(tables) = view.tables() else {
        return (methods, fields);
    };

    // The runs are normalized (clamped to the member tables, non-overlapping) and follow the
    // Ptr tables of a `#-` stream, so a hostile list column cannot sweep in another type's
    // members or rows past the table.
    let method_ranges = tables.member_ranges(MemberList::TypeDefMethods);
    let field_ranges = tables.member_ranges(MemberList::TypeDefFields);

    for type_token in types {
        let type_rid = type_token.row();
        methods.extend(
            tables
                .member_rids(&method_ranges, type_rid)
                .map(|rid| Token::from_parts(TableId::MethodDef, rid)),
        );
        fields.extend(
            tables
                .member_rids(&field_ranges, type_rid)
                .map(|rid| Token::from_parts(TableId::Field, rid)),
        );
    }

    (methods, fields)
}

/// Removes types that have no remaining methods or fields.
///
/// After cleanup, some types may become empty shells with no members.
/// This function identifies and removes such types, returning both the
/// count and the set of removed type tokens for cascading cleanup.
///
/// # Arguments
///
/// * `assembly` - The assembly to modify
/// * `body_tokens` - Pre-computed set of tokens referenced from method bodies
///
/// # Returns
///
/// A tuple of (count of empty types removed, set of removed type tokens).
fn remove_empty_types(
    assembly: &mut CilAssembly,
    body_tokens: &HashSet<Token>,
    request: &CleanupRequest,
) -> (usize, HashSet<Token>) {
    // Collect all TypeDef RIDs referenced in method bodies — these must not be removed
    // even if they have no methods/fields (e.g., value types used with newarr/box/unbox).
    let mut referenced_typedefs: HashSet<u32> = body_tokens
        .iter()
        .filter(|t| t.is_table(TableId::TypeDef))
        .map(|t| t.row())
        .collect();

    // Also collect TypeDef RIDs referenced by surviving field signatures.
    // Types like `__StaticArrayInitTypeSize=N` have no methods/fields of their
    // own but are referenced from FieldDef signature blobs (e.g., for
    // RuntimeHelpers.InitializeArray backing fields). Without this, they'd be
    // incorrectly removed as "empty types", leaving dangling blob references.
    let field_sig_refs = collect_typedefs_from_field_signatures(assembly);
    referenced_typedefs.extend(
        field_sig_refs
            .iter()
            .filter(|t| t.is_table(TableId::TypeDef))
            .map(|t| t.row()),
    );

    // And TypeDef RIDs named by surviving TypeSpec signatures. A type used
    // only as part of a constructed type - a generic argument, an array
    // element - is named nowhere else, and removing it leaves the spec
    // pointing at a row that no longer exists.
    let typespec_sig_refs = collect_typedefs_from_typespec_signatures(assembly);
    referenced_typedefs.extend(
        typespec_sig_refs
            .iter()
            .filter(|t| t.is_table(TableId::TypeDef))
            .map(|t| t.row()),
    );

    // Collect empty type RIDs
    let empty_types: Vec<u32> = {
        let view = assembly.view();
        let Some(tables) = view.tables() else {
            return (0, HashSet::new());
        };

        let Some(typedef_table) = tables.table::<TypeDefRaw>() else {
            return (0, HashSet::new());
        };

        let method_ranges = tables.member_ranges(MemberList::TypeDefMethods);
        let field_ranges = tables.member_ranges(MemberList::TypeDefFields);

        let type_count = typedef_table.row_count;

        let mut empty = Vec::new();

        for type_rid in 1..=type_count {
            let Some(typedef) = typedef_table.get(type_rid).ok().flatten() else {
                continue;
            };

            // Skip <Module> (RID 1) - it's special
            if type_rid == 1 {
                continue;
            }

            // Skip protected types — these were created by code generation
            // and must survive cleanup regardless of whether they appear empty.
            if request.is_protected(Token::from_parts(TableId::TypeDef, type_rid)) {
                continue;
            }

            // Skip types that are still referenced in method bodies.
            // ClassLayout types (explicit-size value types) are also protected
            // when referenced — they exist to provide memory layout for array
            // init data (e.g., `__StaticArrayInitTypeSize=N` backing types).
            if referenced_typedefs.contains(&type_rid) {
                continue;
            }
            // Unreferenced ClassLayout types are safe to remove — they're
            // infrastructure whose consumers have already been deleted.
            // Note: referenced ClassLayout types are already protected above.

            // Calculate method count for this type — only count non-deleted rows.
            // Using the raw range (next_type.method_list - this_type.method_list) is
            // incorrect after deletions: a type whose methods were all deleted still
            // has a non-zero range, so we must check each row individually.
            let live_method_count = tables
                .member_rids(&method_ranges, type_rid)
                .filter(|&rid| !assembly.changes().is_row_deleted(TableId::MethodDef, rid))
                .count();

            // Calculate field count for this type: same logic.
            let live_field_count = tables
                .member_rids(&field_ranges, type_rid)
                .filter(|&rid| !assembly.changes().is_row_deleted(TableId::Field, rid))
                .count();

            // Type is empty if it has no surviving methods and no surviving fields,
            // AND is not an interface or abstract class that legitimately has none.
            if live_method_count == 0 && live_field_count == 0 {
                // Skip interface types — they legitimately have no members in metadata
                // when all their members are inherited or defined elsewhere.
                // ECMA-335 §II.23.1.15: Interface = 0x20
                if typedef.flags & 0x20 != 0 {
                    continue;
                }

                // Skip types that are base classes of other surviving types.
                // Abstract base classes may have no direct members but provide
                // type hierarchy structure that must be preserved.
                let is_base_class = typedef_table
                    .iter()
                    .filter_map(skip_unreadable)
                    .any(|other| {
                        other.rid != type_rid
                            && !empty.contains(&other.rid)
                            && other.extends.tag == TableId::TypeDef
                            && other.extends.row == type_rid
                    });
                if is_base_class {
                    continue;
                }

                // Skip types that appear in InterfaceImpl as the interface being implemented.
                if let Some(iface_impl) = tables.table::<InterfaceImplRaw>() {
                    let is_implemented = iface_impl.iter().filter_map(skip_unreadable).any(|row| {
                        row.interface.tag == TableId::TypeDef && row.interface.row == type_rid
                    });
                    if is_implemented {
                        continue;
                    }
                }

                empty.push(type_rid);
            }
        }

        // A type enclosing a type that stays stays with it, however empty: a nested type
        // cannot exist without its enclosing type (ECMA-335 II.22.32), and deleting the
        // enclosing type would drop the NestedClass row and turn the survivor into a
        // top-level type. The closure walks up the whole enclosing chain of each survivor.
        let empty_set: HashSet<u32> = empty.iter().copied().collect();
        let survivors: HashSet<u32> = (1..=type_count)
            .filter(|rid| !empty_set.contains(rid))
            .filter(|rid| !assembly.changes().is_row_deleted(TableId::TypeDef, *rid))
            .collect();
        let enclosing_survivors = expand_with_enclosing_types(assembly, survivors);
        empty.retain(|rid| !enclosing_survivors.contains(rid));

        empty
    };

    // Remove empty types (in reverse RID order)
    let mut removed: usize = 0;
    let mut removed_tokens = HashSet::new();
    for rid in empty_types.into_iter().rev() {
        if try_remove(assembly, TableId::TypeDef, rid) {
            removed = removed.saturating_add(1);
            removed_tokens.insert(Token::from_parts(TableId::TypeDef, rid));
        }
    }

    (removed, removed_tokens)
}

/// Collects the complete set of MethodDef tokens that are still alive.
///
/// A MethodDef is considered alive if it is referenced from ANY of:
///
/// 1. **IL bytecode** — `call`, `callvirt`, `newobj`, `ldftn`, `ldvirtftn`
///    instructions in surviving method bodies (via `scan_method_body_tokens`)
/// 2. **MethodSpec.method** — generic instantiations that are themselves
///    referenced from IL. A MethodSpec token in IL → its underlying MethodDef
///    is alive.
/// 3. **CustomAttribute.constructor** — attribute constructors on surviving
///    entities.
/// 4. **MethodSemantics.method** — property getters/setters, event add/remove
///    handlers on surviving types.
/// 5. **MethodImpl.method_body / method_declaration** — explicit interface
///    overrides on surviving types.
fn collect_alive_method_tokens(assembly: &CilAssembly) -> HashSet<Token> {
    // Start with IL body tokens (all token operands from surviving method bodies).
    let body_tokens = scan_method_body_tokens(assembly, &HashSet::new());

    let mut alive: HashSet<Token> = body_tokens
        .iter()
        .filter(|t| t.is_table(TableId::MethodDef))
        .copied()
        .collect();

    let view = assembly.view();
    let Some(tables) = view.tables() else {
        return alive;
    };

    // MethodSpec.method → if the MethodSpec token is referenced from IL,
    // the underlying MethodDef is alive.
    if let Some(methodspec_table) = tables.table::<MethodSpecRaw>() {
        for row in methodspec_table {
            let row = match row {
                Ok(row) => row,
                Err(e) => {
                    log::warn!("skipping unreadable metadata row: {e}");
                    continue;
                }
            };
            if assembly
                .changes()
                .is_row_deleted(TableId::MethodSpec, row.rid)
            {
                continue;
            }
            let spec_token = Token::from_parts(TableId::MethodSpec, row.rid);
            if body_tokens.contains(&spec_token) && row.method.token.is_table(TableId::MethodDef) {
                alive.insert(row.method.token);
            }
        }
    }

    // CustomAttribute.constructor → if the attribute is not deleted,
    // its constructor method is alive.
    if let Some(attr_table) = tables.table::<CustomAttributeRaw>() {
        for row in attr_table {
            let row = match row {
                Ok(row) => row,
                Err(e) => {
                    log::warn!("skipping unreadable metadata row: {e}");
                    continue;
                }
            };
            if assembly
                .changes()
                .is_row_deleted(TableId::CustomAttribute, row.rid)
            {
                continue;
            }
            if row.constructor.token.is_table(TableId::MethodDef) {
                alive.insert(row.constructor.token);
            }
        }
    }

    // MethodSemantics.method → property getters/setters, event add/remove.
    // These are alive if the row itself is not deleted.
    if let Some(sem_table) = tables.table::<MethodSemanticsRaw>() {
        for row in sem_table {
            let row = match row {
                Ok(row) => row,
                Err(e) => {
                    log::warn!("skipping unreadable metadata row: {e}");
                    continue;
                }
            };
            if assembly
                .changes()
                .is_row_deleted(TableId::MethodSemantics, row.rid)
            {
                continue;
            }
            let method_token = Token::from_parts(TableId::MethodDef, row.method);
            alive.insert(method_token);
        }
    }

    // MethodImpl.method_body / method_declaration → explicit overrides.
    if let Some(impl_table) = tables.table::<MethodImplRaw>() {
        for row in impl_table {
            let row = match row {
                Ok(row) => row,
                Err(e) => {
                    log::warn!("skipping unreadable metadata row: {e}");
                    continue;
                }
            };
            if assembly
                .changes()
                .is_row_deleted(TableId::MethodImpl, row.rid)
            {
                continue;
            }
            if row.method_body.token.is_table(TableId::MethodDef) {
                alive.insert(row.method_body.token);
            }
            if row.method_declaration.token.is_table(TableId::MethodDef) {
                alive.insert(row.method_declaration.token);
            }
        }
    }

    alive
}

/// Collects the complete set of Field tokens that are still alive.
///
/// A field is considered alive if it is referenced from any surviving method's
/// IL bytecode (`ldfld`, `stfld`, `ldsfld`, `stsfld`, `ldflda`, `ldsflda`).
///
/// Unlike methods, fields have no equivalent to MethodSemantics/MethodImpl/
/// CustomAttribute.constructor that would keep them alive independently of IL.
/// Fields referenced only by FieldRVA/Constant/FieldLayout are dependent
/// entries that get cleaned up when the field itself is removed.
fn collect_alive_field_tokens(assembly: &CilAssembly) -> HashSet<Token> {
    let body_tokens = scan_method_body_tokens(assembly, &HashSet::new());
    body_tokens
        .into_iter()
        .filter(|t| t.is_table(TableId::Field))
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::{
        cilassembly::cleanup::CleanupRequest,
        metadata::{tables::TableId, token::Token},
    };

    #[test]
    fn test_execute_cleanup_empty_request() {
        // This test would require a real assembly, so we just verify
        // the function signature and basic logic
        let request = CleanupRequest::new();
        assert!(request.is_empty());
    }

    #[test]
    fn test_cleanup_request_with_types() {
        let mut request = CleanupRequest::new();
        request.add_type(Token::from_parts(TableId::TypeDef, 5));
        request.add_method(Token::from_parts(TableId::MethodDef, 10));

        assert!(!request.is_empty());
        assert_eq!(request.types_len(), 1);
        assert_eq!(request.methods_len(), 1);
    }
}

#[cfg(test)]
mod examples {
    use super::*;
    use crate::{
        metadata::{token::Token, typesystem::CilTypeRc},
        testkit::fixture,
        CilObject, CleanupRequest, Result,
    };

    /// The type and the types nested in it, recursively.
    fn with_nested(ty: &CilTypeRc) -> Vec<CilTypeRc> {
        let mut all = vec![ty.clone()];
        for (_, nested) in ty.nested_types.iter() {
            if let Some(nested) = nested.upgrade() {
                all.extend(with_nested(&nested));
            }
        }
        all
    }

    /// Deleting a type deletes its methods and the types nested in it, and the statistics
    /// say so.
    #[test]
    fn execute_cleanup_example() -> Result<()> {
        let sample = fixture("packers/confuserex/1.6.0/original.exe");
        let doomed = Token::new(0x0200_0002);
        let object = CilObject::from_path(&sample)?;
        let removed = with_nested(&object.types().get(&doomed).expect("the type"));
        let methods: usize = removed.iter().map(|ty| ty.methods.count()).sum();
        assert!(methods > 0);

        let mut assembly = CilAssembly::from_path(&sample)?;
        let mut request = CleanupRequest::new();
        request.add_type(doomed);

        let stats = execute_cleanup(&mut assembly, &request)?;
        assert_eq!(stats.get(TableId::TypeDef), removed.len());
        assert_eq!(stats.get(TableId::MethodDef), methods);
        Ok(())
    }
}

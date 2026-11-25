//! Dependent metadata removal and cascade cleanup.
//!
//! This module provides functions to find and remove metadata entries that
//! depend on deleted entities. It has two phases:
//!
//! **Phase A — Parent-child cleanup**: Removes metadata entries that directly
//! reference deleted entities (Params, ClassLayout, FieldRVA, NestedClass, etc.)
//!
//! **Phase B — Cascade reference cleanup**: Using pre-deletion reference data,
//! removes TypeRef/MemberRef/TypeSpec/ModuleRef/AssemblyRef entries that were
//! *exclusively* referenced by deleted entities and are no longer referenced
//! by any surviving entity.
//!
//! # Design Principle
//!
//! These functions only remove entries that were referenced by deleted items.
//! They do NOT remove pre-existing orphaned entries in the original assembly,
//! as those may be intentionally orphaned (e.g., used via reflection).

use std::collections::{BTreeSet, HashSet};

use crate::{
    cilassembly::{
        cleanup::{
            references::{
                collect_referenced_standalonesig_rids,
                collect_typerefs_from_deleted_memberref_sigs, remove_unreferenced_memberrefs,
                remove_unreferenced_typerefs, remove_unreferenced_typespecs, rows_of,
                scan_metadata_keepers, PreDeletionRefs,
            },
            utils::{remove_candidates_not_alive, try_remove},
            CleanupStats,
        },
        CilAssembly,
    },
    metadata::{
        streams::TablesHeader,
        tables::{
            ClassLayoutRaw, ConstantRaw, CustomAttributeRaw, DeclSecurityRaw, EventMapRaw,
            EventRaw, ExportedTypeRaw, FieldLayoutRaw, FieldMarshalRaw, FieldRvaRaw,
            GenericParamConstraintRaw, GenericParamRaw, ImplMapRaw, InterfaceImplRaw,
            ManifestResourceRaw, MemberList, MemberRefRaw, MethodDefRaw, MethodImplRaw,
            MethodSemanticsRaw, MethodSpecRaw, NestedClassRaw, ParamRaw, PropertyMapRaw,
            PropertyRaw, RowReadable, StandAloneSigRaw, TableAccess, TableId, TypeRefRaw,
        },
        token::Token,
    },
};

/// Context for deletion-aware cleanup operations.
///
/// Tracks which tokens have been deleted, allowing cleanup functions
/// to determine what dependent metadata should be removed.
///
/// This struct holds references to the deleted token sets to avoid
/// unnecessary copying during cleanup operations.
#[derive(Debug, Clone, Copy)]
pub struct DeletionContext<'a> {
    /// Types (TypeDef) that have been deleted.
    types: &'a HashSet<Token>,
    /// Methods (MethodDef) that have been deleted.
    methods: &'a HashSet<Token>,
    /// Fields that have been deleted.
    fields: &'a HashSet<Token>,
}

impl<'a> DeletionContext<'a> {
    /// Creates a new deletion context from references to deleted token sets.
    #[must_use]
    pub fn new(
        deleted_types: &'a HashSet<Token>,
        deleted_methods: &'a HashSet<Token>,
        deleted_fields: &'a HashSet<Token>,
    ) -> Self {
        Self {
            types: deleted_types,
            methods: deleted_methods,
            fields: deleted_fields,
        }
    }

    /// Returns true if the given token has been deleted.
    ///
    /// Checks all three token sets (types, methods, fields).
    #[must_use]
    pub fn is_deleted(&self, token: Token) -> bool {
        self.types.contains(&token) || self.methods.contains(&token) || self.fields.contains(&token)
    }

    /// Returns true if the given type token has been deleted.
    #[must_use]
    pub fn is_type_deleted(&self, token: Token) -> bool {
        self.types.contains(&token)
    }

    /// Returns true if the given method token has been deleted.
    #[must_use]
    pub fn is_method_deleted(&self, token: Token) -> bool {
        self.methods.contains(&token)
    }

    /// Returns true if the given field token has been deleted.
    #[must_use]
    pub fn is_field_deleted(&self, token: Token) -> bool {
        self.fields.contains(&token)
    }
}

/// Generic helper to remove orphaned entries from a table.
///
/// Iterates through a table and removes entries for which the predicate
/// returns `true`. Entries are removed in reverse RID order to maintain
/// consistent indexing during removal.
///
/// # Type Parameters
///
/// * `T` - The raw table row type (e.g., `ParamRaw`, `CustomAttributeRaw`)
///
/// # Arguments
///
/// * `assembly` - The assembly to modify
/// * `is_orphan` - Closure that returns `true` if a row should be removed
///
/// # Returns
///
/// The count of removed entries.
pub fn remove_orphan_entries<T>(assembly: &mut CilAssembly, is_orphan: impl Fn(&T) -> bool) -> usize
where
    T: RowReadable,
    for<'a> TablesHeader<'a>: TableAccess<'a, T>,
{
    // First pass: collect orphan RIDs (immutable borrow)
    let orphan_rids: Vec<u32> = {
        let view = assembly.view();
        let Some(tables) = view.tables() else {
            return 0;
        };

        let Some(table) = tables.table::<T>() else {
            return 0;
        };

        (1..=table.row_count)
            .filter_map(|rid| {
                table
                    .get(rid)
                    .ok()
                    .flatten()
                    .filter(|r| is_orphan(r))
                    .map(|_| rid)
            })
            .collect()
    };

    // Second pass: remove in reverse order (mutable borrow)
    let mut removed_count: usize = 0;
    for rid in orphan_rids.into_iter().rev() {
        if try_remove(assembly, T::TABLE_ID, rid) {
            removed_count = removed_count.saturating_add(1);
        }
    }

    removed_count
}

/// Removes orphaned Param entries for deleted methods.
///
/// Parameters belong to methods via the `param_list` field in MethodDef.
/// When a method is deleted, its parameters become orphaned.
///
/// Returns the removed Param RIDs alongside the count. Rows in other tables
/// point at parameters through a coded index — `Constant` for a default value,
/// `FieldMarshal` for marshalling information, `CustomAttribute` for anything
/// applied to the parameter — and those rows are dropped by asking
/// [`DeletionContext`] whether their parent went away. A parameter removed here
/// never enters that context: what was deleted is the *method*, and the context
/// is immutable by the time this runs. Without the RIDs, every such dependent
/// outlives the parameter it names and leaves a reference to a row that no
/// longer exists.
pub fn remove_orphan_params(
    assembly: &mut CilAssembly,
    ctx: &DeletionContext,
) -> (usize, HashSet<u32>) {
    // Collect param RIDs that belong to deleted methods (immutable borrow scope)
    let mut orphan_params: Vec<u32> = {
        let view = assembly.view();
        let Some(tables) = view.tables() else {
            return (0, HashSet::new());
        };

        let Some(methoddef_table) = tables.table::<MethodDefRaw>() else {
            return (0, HashSet::new());
        };

        if tables.table::<ParamRaw>().is_none() {
            return (0, HashSet::new());
        }

        let method_count = methoddef_table.row_count;
        let param_ranges = tables.member_ranges(MemberList::MethodDefParams);

        let mut params = Vec::new();
        for method_rid in 1..=method_count {
            let method_token = Token::from_parts(TableId::MethodDef, method_rid);

            if !ctx.is_method_deleted(method_token) {
                continue;
            }

            params.extend(tables.member_rids(&param_ranges, method_rid));
        }
        params
    };

    // Remove collected orphans (in descending RID order)
    orphan_params.sort_unstable_by(|a, b| b.cmp(a));
    orphan_params.dedup();

    let mut removed_count: usize = 0;
    let mut removed_rids: HashSet<u32> = HashSet::new();
    for rid in orphan_params {
        if try_remove(assembly, TableId::Param, rid) {
            removed_count = removed_count.saturating_add(1);
            removed_rids.insert(rid);
        }
    }

    (removed_count, removed_rids)
}

/// Whether `parent` names one of the parameters removed by
/// [`remove_orphan_params`].
///
/// The coded index carries the table in the token, so a RID collision with
/// another table cannot be mistaken for a match.
fn names_removed_param(parent: Token, removed_params: &HashSet<u32>) -> bool {
    parent.table() == TableId::Param.token_type() && removed_params.contains(&parent.row())
}

/// Removes orphaned CustomAttribute entries for deleted tokens.
///
/// Custom attributes reference their parent via the `parent` coded index,
/// and their constructor via the `constructor` coded index.
/// When either the parent or constructor is deleted, the attribute becomes orphaned.
pub fn remove_orphan_attributes(
    assembly: &mut CilAssembly,
    ctx: &DeletionContext,
    removed_params: &HashSet<u32>,
) -> usize {
    remove_orphan_entries::<CustomAttributeRaw>(assembly, |attr| {
        // Remove if parent is deleted
        if ctx.is_deleted(attr.parent.token) {
            return true;
        }
        // A parameter dropped with its method is gone without being recorded as
        // deleted, so it has to be matched separately.
        if names_removed_param(attr.parent.token, removed_params) {
            return true;
        }
        // Also remove if constructor method is deleted (MethodDef or MemberRef)
        ctx.is_deleted(attr.constructor.token)
    })
}

/// Removes orphaned ClassLayout entries for deleted types.
pub fn remove_orphan_classlayouts(assembly: &mut CilAssembly, ctx: &DeletionContext) -> usize {
    remove_orphan_entries::<ClassLayoutRaw>(assembly, |layout| {
        let parent_token = Token::from_parts(TableId::TypeDef, layout.parent);
        ctx.is_type_deleted(parent_token)
    })
}

/// Removes orphaned FieldRVA entries for deleted fields.
pub fn remove_orphan_fieldrvas(assembly: &mut CilAssembly, ctx: &DeletionContext) -> usize {
    remove_orphan_entries::<FieldRvaRaw>(assembly, |rva| {
        let field_token = Token::from_parts(TableId::Field, rva.field);
        ctx.is_field_deleted(field_token)
    })
}

/// Removes orphaned NestedClass entries for deleted types.
pub fn remove_orphan_nestedclass(assembly: &mut CilAssembly, ctx: &DeletionContext) -> usize {
    remove_orphan_entries::<NestedClassRaw>(assembly, |nested| {
        let nested_token = Token::from_parts(TableId::TypeDef, nested.nested_class);
        let enclosing_token = Token::from_parts(TableId::TypeDef, nested.enclosing_class);
        ctx.is_type_deleted(nested_token) || ctx.is_type_deleted(enclosing_token)
    })
}

/// Removes orphaned InterfaceImpl entries for deleted types.
pub fn remove_orphan_interfaceimpl(assembly: &mut CilAssembly, ctx: &DeletionContext) -> usize {
    remove_orphan_entries::<InterfaceImplRaw>(assembly, |impl_| {
        let class_token = Token::from_parts(TableId::TypeDef, impl_.class);
        ctx.is_type_deleted(class_token)
    })
}

/// Removes orphaned MethodImpl entries for deleted types or methods.
pub fn remove_orphan_methodimpl(assembly: &mut CilAssembly, ctx: &DeletionContext) -> usize {
    remove_orphan_entries::<MethodImplRaw>(assembly, |impl_| {
        let class_token = Token::from_parts(TableId::TypeDef, impl_.class);

        // Check class and method_body and method_declaration (MethodDefOrRef coded index)
        ctx.is_type_deleted(class_token)
            || ctx.is_deleted(impl_.method_body.token)
            || ctx.is_deleted(impl_.method_declaration.token)
    })
}

/// Removes orphaned MethodSemantics entries for deleted methods, events, or properties.
///
/// Checks both the `method` field (MethodDef that was deleted) and the `association`
/// field (Event or Property that was deleted).
pub fn remove_orphan_methodsemantics(
    assembly: &mut CilAssembly,
    ctx: &DeletionContext,
    deleted_events: &HashSet<Token>,
    deleted_properties: &HashSet<Token>,
) -> usize {
    remove_orphan_entries::<MethodSemanticsRaw>(assembly, |sem| {
        let method_token = Token::from_parts(TableId::MethodDef, sem.method);
        ctx.is_method_deleted(method_token)
            || deleted_events.contains(&sem.association.token)
            || deleted_properties.contains(&sem.association.token)
    })
}

/// Removes orphaned Constant entries for deleted fields, properties or params.
pub fn remove_orphan_constant(
    assembly: &mut CilAssembly,
    ctx: &DeletionContext,
    removed_params: &HashSet<u32>,
) -> usize {
    remove_orphan_entries::<ConstantRaw>(assembly, |constant| {
        ctx.is_deleted(constant.parent.token)
            || names_removed_param(constant.parent.token, removed_params)
    })
}

/// Removes orphaned FieldMarshal entries for deleted fields or params.
pub fn remove_orphan_fieldmarshal(
    assembly: &mut CilAssembly,
    ctx: &DeletionContext,
    removed_params: &HashSet<u32>,
) -> usize {
    remove_orphan_entries::<FieldMarshalRaw>(assembly, |marshal| {
        ctx.is_deleted(marshal.parent.token)
            || names_removed_param(marshal.parent.token, removed_params)
    })
}

/// Removes orphaned FieldLayout entries for deleted fields.
pub fn remove_orphan_fieldlayout(assembly: &mut CilAssembly, ctx: &DeletionContext) -> usize {
    remove_orphan_entries::<FieldLayoutRaw>(assembly, |layout| {
        let field_token = Token::from_parts(TableId::Field, layout.field);
        ctx.is_field_deleted(field_token)
    })
}

/// Removes orphaned GenericParam entries for deleted types or methods.
///
/// Returns the set of removed GenericParam RIDs for cascading to constraints.
pub fn remove_orphan_genericparam(
    assembly: &mut CilAssembly,
    ctx: &DeletionContext,
) -> (usize, HashSet<u32>) {
    // First pass: collect orphan RIDs
    let orphan_rids: Vec<u32> = {
        let view = assembly.view();
        let Some(tables) = view.tables() else {
            return (0, HashSet::new());
        };

        let Some(table) = tables.table::<GenericParamRaw>() else {
            return (0, HashSet::new());
        };

        (1..=table.row_count)
            .filter_map(|rid| {
                table.get(rid).ok().flatten().and_then(|param| {
                    if ctx.is_deleted(param.owner.token) {
                        Some(rid)
                    } else {
                        None
                    }
                })
            })
            .collect()
    };

    let removed_rids: HashSet<u32> = orphan_rids.iter().copied().collect();

    // Second pass: remove
    let mut removed_count: usize = 0;
    for rid in orphan_rids.into_iter().rev() {
        if try_remove(assembly, TableId::GenericParam, rid) {
            removed_count = removed_count.saturating_add(1);
        }
    }

    (removed_count, removed_rids)
}

/// Removes orphaned GenericParamConstraint entries for removed GenericParams.
pub fn remove_orphan_genericparamconstraint(
    assembly: &mut CilAssembly,
    removed_genericparams: &HashSet<u32>,
) -> usize {
    remove_orphan_entries::<GenericParamConstraintRaw>(assembly, |constraint| {
        removed_genericparams.contains(&constraint.owner)
    })
}

/// Removes orphaned MethodSpec entries for deleted methods.
pub fn remove_orphan_methodspec(assembly: &mut CilAssembly, ctx: &DeletionContext) -> usize {
    remove_orphan_entries::<MethodSpecRaw>(assembly, |spec| ctx.is_deleted(spec.method.token))
}

/// Removes orphaned DeclSecurity entries for deleted types or methods.
pub fn remove_orphan_declsecurity(assembly: &mut CilAssembly, ctx: &DeletionContext) -> usize {
    remove_orphan_entries::<DeclSecurityRaw>(assembly, |security| {
        ctx.is_deleted(security.parent.token)
    })
}

/// Removes orphaned ImplMap entries for deleted methods (P/Invoke).
pub fn remove_orphan_implmap(assembly: &mut CilAssembly, ctx: &DeletionContext) -> usize {
    remove_orphan_entries::<ImplMapRaw>(assembly, |implmap| {
        ctx.is_deleted(implmap.member_forwarded.token)
    })
}

/// Removes orphaned EventMap entries for deleted types.
pub fn remove_orphan_eventmap(assembly: &mut CilAssembly, ctx: &DeletionContext) -> usize {
    remove_orphan_entries::<EventMapRaw>(assembly, |eventmap| {
        let parent_token = Token::from_parts(TableId::TypeDef, eventmap.parent);
        ctx.is_type_deleted(parent_token)
    })
}

/// Removes orphaned PropertyMap entries for deleted types.
pub fn remove_orphan_propertymap(assembly: &mut CilAssembly, ctx: &DeletionContext) -> usize {
    remove_orphan_entries::<PropertyMapRaw>(assembly, |propmap| {
        let parent_token = Token::from_parts(TableId::TypeDef, propmap.parent);
        ctx.is_type_deleted(parent_token)
    })
}

/// Removes orphaned Event entries for deleted types.
///
/// Events belong to types via EventMap's list-style ownership (like MethodDef's param_list).
/// When a type is deleted, its events become orphaned.
///
/// Returns a tuple of (count_removed, set_of_deleted_event_tokens).
pub fn remove_orphan_events(
    assembly: &mut CilAssembly,
    ctx: &DeletionContext,
) -> (usize, HashSet<Token>) {
    let mut orphan_events: Vec<u32> = {
        let view = assembly.view();
        let Some(tables) = view.tables() else {
            return (0, HashSet::new());
        };

        let Some(eventmap_table) = tables.table::<EventMapRaw>() else {
            return (0, HashSet::new());
        };

        if tables.table::<EventRaw>().is_none() {
            return (0, HashSet::new());
        }

        let map_count = eventmap_table.row_count;
        let event_ranges = tables.member_ranges(MemberList::EventMapEvents);
        let mut events = Vec::new();

        for map_rid in 1..=map_count {
            let Some(eventmap) = eventmap_table.get(map_rid).ok().flatten() else {
                continue;
            };
            let parent_token = Token::from_parts(TableId::TypeDef, eventmap.parent);
            if !ctx.is_type_deleted(parent_token) {
                continue;
            }

            events.extend(tables.member_rids(&event_ranges, map_rid));
        }
        events
    };

    orphan_events.sort_unstable_by(|a, b| b.cmp(a));
    orphan_events.dedup();

    let mut removed: usize = 0;
    let mut deleted_tokens = HashSet::new();
    for rid in orphan_events {
        if try_remove(assembly, TableId::Event, rid) {
            removed = removed.saturating_add(1);
            deleted_tokens.insert(Token::from_parts(TableId::Event, rid));
        }
    }

    (removed, deleted_tokens)
}

/// Removes orphaned Property entries for deleted types.
///
/// Properties belong to types via PropertyMap's list-style ownership.
/// When a type is deleted, its properties become orphaned.
///
/// Returns a tuple of (count_removed, set_of_deleted_property_tokens).
pub fn remove_orphan_properties(
    assembly: &mut CilAssembly,
    ctx: &DeletionContext,
) -> (usize, HashSet<Token>) {
    let mut orphan_properties: Vec<u32> = {
        let view = assembly.view();
        let Some(tables) = view.tables() else {
            return (0, HashSet::new());
        };

        let Some(propertymap_table) = tables.table::<PropertyMapRaw>() else {
            return (0, HashSet::new());
        };

        if tables.table::<PropertyRaw>().is_none() {
            return (0, HashSet::new());
        }

        let map_count = propertymap_table.row_count;
        let property_ranges = tables.member_ranges(MemberList::PropertyMapProperties);
        let mut props = Vec::new();

        for map_rid in 1..=map_count {
            let Some(propertymap) = propertymap_table.get(map_rid).ok().flatten() else {
                continue;
            };
            let parent_token = Token::from_parts(TableId::TypeDef, propertymap.parent);
            if !ctx.is_type_deleted(parent_token) {
                continue;
            }

            props.extend(tables.member_rids(&property_ranges, map_rid));
        }
        props
    };

    orphan_properties.sort_unstable_by(|a, b| b.cmp(a));
    orphan_properties.dedup();

    let mut removed: usize = 0;
    let mut deleted_tokens = HashSet::new();
    for rid in orphan_properties {
        if try_remove(assembly, TableId::Property, rid) {
            removed = removed.saturating_add(1);
            deleted_tokens.insert(Token::from_parts(TableId::Property, rid));
        }
    }

    (removed, deleted_tokens)
}

/// Removes orphaned StandAloneSig entries using cascade-from-deleted semantics.
///
/// Of the `candidates`, removes the entries no surviving method body uses, through its
/// header's local variable signature or a `calli` operand among `body_tokens`.
///
/// This preserves pre-existing orphaned StandAloneSigs that may be used via
/// reflection or dynamic code generation.
pub fn remove_orphan_standalonesigs(
    assembly: &mut CilAssembly,
    candidates: &BTreeSet<u32>,
    body_tokens: &HashSet<Token>,
) -> usize {
    if candidates.is_empty() {
        return 0;
    }

    let alive = collect_referenced_standalonesig_rids(assembly, body_tokens);

    let mut removed: usize = 0;
    for &rid in candidates.iter().rev() {
        if !alive.contains(&rid) && try_remove(assembly, TableId::StandAloneSig, rid) {
            removed = removed.saturating_add(1);
        }
    }

    removed
}

/// Removes cascade-candidate `ModuleRef` entries that are no longer referenced.
///
/// Only removes ModuleRef entries that are in the `candidates` set AND are not
/// referenced by any surviving `ImplMap`, `MemberRef` class or `TypeRef` resolution scope.
///
/// Must be called **after** `remove_orphan_implmap`, `remove_unreferenced_memberrefs` and
/// `remove_unreferenced_typerefs` to ensure cascaded deletions are accounted for.
pub fn remove_orphan_modulerefs(assembly: &mut CilAssembly, candidates: &BTreeSet<u32>) -> usize {
    if candidates.is_empty() {
        return 0;
    }

    // Collect ModuleRef RIDs still referenced by surviving ImplMap and TypeRef entries
    let alive: HashSet<u32> =
        rows_of(&scan_metadata_keepers(assembly), TableId::ModuleRef).collect();

    let (removed, _) =
        remove_candidates_not_alive(assembly, TableId::ModuleRef, candidates, &alive);
    removed
}

/// Removes cascade-candidate `AssemblyRef` entries that are no longer referenced.
///
/// Only removes AssemblyRef entries that are in the `candidates` set AND are not
/// referenced by any surviving `TypeRef` resolution scope, `ExportedType` (a type forwarder)
/// or `ManifestResource` another assembly holds.
///
/// Must be called **after** `remove_unreferenced_typerefs` to ensure cascaded
/// TypeRef deletions are accounted for.
pub fn remove_orphan_assemblyrefs(assembly: &mut CilAssembly, candidates: &BTreeSet<u32>) -> usize {
    if candidates.is_empty() {
        return 0;
    }

    let alive: HashSet<u32> =
        rows_of(&scan_metadata_keepers(assembly), TableId::AssemblyRef).collect();
    let (removed, _) =
        remove_candidates_not_alive(assembly, TableId::AssemblyRef, candidates, &alive);
    removed
}

/// Removes orphaned ExportedType entries whose implementation target has been deleted.
///
/// ExportedType entries reference AssemblyRef, File, or other ExportedType entries
/// via their `implementation` coded index. When those targets are cascade-deleted,
/// the ExportedType becomes invalid.
///
/// Returns a tuple of (count_removed, set_of_deleted_rids) for cascading to File.
pub fn remove_orphan_exportedtypes(assembly: &mut CilAssembly) -> (usize, HashSet<u32>) {
    // Two-pass: collect then remove (can't use remove_orphan_entries because
    // the closure needs assembly access for is_row_deleted)
    let orphan_rids: Vec<u32> = {
        let view = assembly.view();
        let Some(tables) = view.tables() else {
            return (0, HashSet::new());
        };

        let Some(table) = tables.table::<ExportedTypeRaw>() else {
            return (0, HashSet::new());
        };

        (1..=table.row_count)
            .filter_map(|rid| {
                let entry = table.get(rid).ok().flatten()?;
                // Null implementation (row == 0) means type is defined in this module
                if entry.implementation.row == 0 {
                    return None;
                }
                if assembly
                    .changes()
                    .is_row_deleted(entry.implementation.tag, entry.implementation.row)
                {
                    Some(rid)
                } else {
                    None
                }
            })
            .collect()
    };

    let mut deleted_rids = HashSet::new();
    let mut removed: usize = 0;
    for rid in orphan_rids.into_iter().rev() {
        if try_remove(assembly, TableId::ExportedType, rid) {
            removed = removed.saturating_add(1);
            deleted_rids.insert(rid);
        }
    }

    (removed, deleted_rids)
}

/// Removes orphaned ManifestResource entries whose implementation target has been deleted.
///
/// ManifestResource.implementation is a coded index pointing to File, AssemblyRef,
/// or null (embedded in current module). When the target is cascade-deleted,
/// the ManifestResource becomes invalid.
///
/// Returns a tuple of (count_removed, set_of_deleted_rids) for cascading to File.
pub fn remove_orphan_manifestresources(assembly: &mut CilAssembly) -> (usize, HashSet<u32>) {
    let orphan_rids: Vec<u32> = {
        let view = assembly.view();
        let Some(tables) = view.tables() else {
            return (0, HashSet::new());
        };

        let Some(table) = tables.table::<ManifestResourceRaw>() else {
            return (0, HashSet::new());
        };

        (1..=table.row_count)
            .filter_map(|rid| {
                let entry = table.get(rid).ok().flatten()?;
                // Null implementation (row == 0) = embedded resource, skip
                if entry.implementation.row == 0 {
                    return None;
                }
                if assembly
                    .changes()
                    .is_row_deleted(entry.implementation.tag, entry.implementation.row)
                {
                    Some(rid)
                } else {
                    None
                }
            })
            .collect()
    };

    let mut deleted_rids = HashSet::new();
    let mut removed: usize = 0;
    for rid in orphan_rids.into_iter().rev() {
        if try_remove(assembly, TableId::ManifestResource, rid) {
            removed = removed.saturating_add(1);
            deleted_rids.insert(rid);
        }
    }

    (removed, deleted_rids)
}

/// Removes cascade-candidate File entries that are no longer referenced.
///
/// Only removes File entries that are in the `candidates` set AND are not
/// referenced by any surviving ExportedType or ManifestResource entry.
pub fn remove_orphan_files(assembly: &mut CilAssembly, candidates: &BTreeSet<u32>) -> usize {
    if candidates.is_empty() {
        return 0;
    }

    let alive: HashSet<u32> = rows_of(&scan_metadata_keepers(assembly), TableId::File).collect();

    let (removed, _) = remove_candidates_not_alive(assembly, TableId::File, candidates, &alive);
    removed
}

/// Removes all metadata entries that depend on deleted types.
///
/// This covers the full set of type-dependent tables: NestedClass, InterfaceImpl,
/// CustomAttribute, ClassLayout, EventMap, PropertyMap, Event rows, Property rows,
/// DeclSecurity, MethodImpl, MethodSemantics, GenericParam and GenericParamConstraint.
///
/// Called from both the main orphan pass and the empty-types pass to ensure
/// both paths stay in sync.
pub fn remove_type_dependents(assembly: &mut CilAssembly, ctx: &DeletionContext) -> CleanupStats {
    let mut stats = CleanupStats::new();
    stats.add(
        TableId::NestedClass,
        remove_orphan_nestedclass(assembly, ctx),
    );
    stats.add(
        TableId::InterfaceImpl,
        remove_orphan_interfaceimpl(assembly, ctx),
    );
    stats.add(
        TableId::CustomAttribute,
        remove_orphan_attributes(assembly, ctx, &HashSet::new()),
    );
    stats.add(
        TableId::ClassLayout,
        remove_orphan_classlayouts(assembly, ctx),
    );
    stats.add(TableId::EventMap, remove_orphan_eventmap(assembly, ctx));
    stats.add(
        TableId::PropertyMap,
        remove_orphan_propertymap(assembly, ctx),
    );
    let (events_removed, deleted_events) = remove_orphan_events(assembly, ctx);
    stats.add(TableId::Event, events_removed);
    let (properties_removed, deleted_properties) = remove_orphan_properties(assembly, ctx);
    stats.add(TableId::Property, properties_removed);
    stats.add(
        TableId::DeclSecurity,
        remove_orphan_declsecurity(assembly, ctx),
    );
    stats.add(TableId::MethodImpl, remove_orphan_methodimpl(assembly, ctx));
    stats.add(
        TableId::MethodSemantics,
        remove_orphan_methodsemantics(assembly, ctx, &deleted_events, &deleted_properties),
    );
    let (gp, gp_rids) = remove_orphan_genericparam(assembly, ctx);
    stats.add(TableId::GenericParam, gp);
    stats.add(
        TableId::GenericParamConstraint,
        remove_orphan_genericparamconstraint(assembly, &gp_rids),
    );
    stats
}

/// Phase A: Removes metadata entries that directly depend on deleted entities.
///
/// This handles parent-child cleanup: params, attributes, ClassLayout, FieldRVA,
/// NestedClass, InterfaceImpl, EventMap, PropertyMap, Event/Property rows,
/// MethodImpl, MethodSemantics, ImplMap, DeclSecurity, MethodSpec, StandAloneSig,
/// field-related tables, GenericParam and GenericParamConstraint. `body_tokens` are the
/// tokens surviving method bodies reference.
pub fn remove_parent_child_dependents(
    assembly: &mut CilAssembly,
    ctx: &DeletionContext,
    _pre_refs: &PreDeletionRefs,
    body_tokens: &HashSet<Token>,
) -> CleanupStats {
    let mut stats = CleanupStats::new();

    // 1. Params (depend on methods)
    let (params, removed_params) = remove_orphan_params(assembly, ctx);
    stats.add(TableId::Param, params);

    // 2. Custom attributes (can target anything, parameters included)
    stats.add(
        TableId::CustomAttribute,
        remove_orphan_attributes(assembly, ctx, &removed_params),
    );

    // 3. Type-related tables
    stats.add(
        TableId::ClassLayout,
        remove_orphan_classlayouts(assembly, ctx),
    );
    stats.add(
        TableId::NestedClass,
        remove_orphan_nestedclass(assembly, ctx),
    );
    stats.add(
        TableId::InterfaceImpl,
        remove_orphan_interfaceimpl(assembly, ctx),
    );
    stats.add(TableId::EventMap, remove_orphan_eventmap(assembly, ctx));
    stats.add(
        TableId::PropertyMap,
        remove_orphan_propertymap(assembly, ctx),
    );

    // 3b. Event and Property rows (owned by EventMap/PropertyMap via list)
    let (events_removed, deleted_events) = remove_orphan_events(assembly, ctx);
    stats.add(TableId::Event, events_removed);
    let (properties_removed, deleted_properties) = remove_orphan_properties(assembly, ctx);
    stats.add(TableId::Property, properties_removed);

    // 4. Method-related tables
    stats.add(TableId::MethodImpl, remove_orphan_methodimpl(assembly, ctx));
    stats.add(
        TableId::MethodSemantics,
        remove_orphan_methodsemantics(assembly, ctx, &deleted_events, &deleted_properties),
    );
    stats.add(TableId::ImplMap, remove_orphan_implmap(assembly, ctx));
    stats.add(
        TableId::DeclSecurity,
        remove_orphan_declsecurity(assembly, ctx),
    );
    stats.add(TableId::MethodSpec, remove_orphan_methodspec(assembly, ctx));
    // StandAloneSig entries are referenced from method bodies only: a header's local
    // variable signature or a `calli` operand. After method deletion and body regeneration,
    // old SAS entries become orphaned. Scan ALL SAS entries as candidates
    // since there is no reflection mechanism that references SAS by token.
    {
        let all_sas_rids: BTreeSet<u32> = {
            let view = assembly.view();
            view.tables()
                .and_then(|t| t.table::<StandAloneSigRaw>())
                .map(|table| {
                    (1..=table.row_count)
                        .filter(|&rid| {
                            !assembly
                                .changes()
                                .is_row_deleted(TableId::StandAloneSig, rid)
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        stats.add(
            TableId::StandAloneSig,
            remove_orphan_standalonesigs(assembly, &all_sas_rids, body_tokens),
        );
    }

    // 5. Field-related tables
    stats.add(TableId::FieldRVA, remove_orphan_fieldrvas(assembly, ctx));
    stats.add(
        TableId::FieldLayout,
        remove_orphan_fieldlayout(assembly, ctx),
    );
    stats.add(
        TableId::FieldMarshal,
        remove_orphan_fieldmarshal(assembly, ctx, &removed_params),
    );
    stats.add(
        TableId::Constant,
        remove_orphan_constant(assembly, ctx, &removed_params),
    );

    // 6. Generic params (and cascade to constraints)
    let (genericparams, removed_gp_rids) = remove_orphan_genericparam(assembly, ctx);
    stats.add(TableId::GenericParam, genericparams);
    stats.add(
        TableId::GenericParamConstraint,
        remove_orphan_genericparamconstraint(assembly, &removed_gp_rids),
    );

    stats
}

/// Phase B: Cascade-removes reference entries that are no longer alive.
///
/// Removes MemberRef → TypeRef → ModuleRef/AssemblyRef → ExportedType/File
/// entries that were exclusively referenced by deleted entities.
///
/// Uses pre-deletion reference data combined with full table scans to include
/// ALL non-deleted entries as candidates, catching entries orphaned by both
/// entity deletion and method body regeneration.
pub fn cascade_reference_cleanup(
    assembly: &mut CilAssembly,
    pre_refs: &PreDeletionRefs,
    body_tokens: &HashSet<Token>,
) -> CleanupStats {
    let mut stats = CleanupStats::new();

    // 7a. Compute MemberRef cascade candidates from pre-deletion IL tokens.
    // Include ALL non-deleted MemberRef RIDs to also catch entries orphaned
    // by method body regeneration.
    let mut memberref_candidates: BTreeSet<u32> = pre_refs
        .il_tokens
        .iter()
        .filter(|t| t.is_table(TableId::MemberRef))
        .map(|t| t.row())
        .collect();

    {
        let view = assembly.view();
        if let Some(tables) = view.tables() {
            if let Some(memberref_table) = tables.table::<MemberRefRaw>() {
                for memberref in memberref_table {
                    let memberref = match memberref {
                        Ok(row) => row,
                        Err(e) => {
                            log::warn!("skipping unreadable metadata row: {e}");
                            continue;
                        }
                    };
                    if !assembly
                        .changes()
                        .is_row_deleted(TableId::MemberRef, memberref.rid)
                    {
                        memberref_candidates.insert(memberref.rid);
                    }
                }
            }
        }
    }

    let (memberrefs_removed, deleted_memberref_rids) =
        remove_unreferenced_memberrefs(assembly, &memberref_candidates, body_tokens);
    stats.add(TableId::MemberRef, memberrefs_removed);

    // 7b. Compute TypeSpec cascade candidates from pre-deletion IL tokens.
    // Include ALL non-deleted TypeSpec RIDs.
    let mut typespec_candidates: BTreeSet<u32> = pre_refs
        .il_tokens
        .iter()
        .filter(|t| t.is_table(TableId::TypeSpec))
        .map(|t| t.row())
        .collect();

    {
        let view = assembly.view();
        if let Some(tables) = view.tables() {
            if let Some(typespec_table) = tables.table::<crate::metadata::tables::TypeSpecRaw>() {
                for typespec in typespec_table {
                    let typespec = match typespec {
                        Ok(row) => row,
                        Err(e) => {
                            log::warn!("skipping unreadable metadata row: {e}");
                            continue;
                        }
                    };
                    if !assembly
                        .changes()
                        .is_row_deleted(TableId::TypeSpec, typespec.rid)
                    {
                        typespec_candidates.insert(typespec.rid);
                    }
                }
            }
        }
    }

    let (typespecs_removed, _deleted_typespec_rids) =
        remove_unreferenced_typespecs(assembly, &typespec_candidates, body_tokens);
    stats.add(TableId::TypeSpec, typespecs_removed);

    // 7c. Compute TypeRef cascade candidates:
    //     - From pre-deletion IL tokens
    //     - From pre-deletion signature/extends TypeRef RIDs
    //     - From cascade: class of deleted MemberRefs
    let mut typeref_candidates: BTreeSet<u32> = pre_refs
        .il_tokens
        .iter()
        .filter(|t| t.is_table(TableId::TypeRef))
        .map(|t| t.row())
        .chain(pre_refs.typeref_rids.iter().copied())
        .collect();

    // Add TypeRefs from cascade-deleted MemberRefs:
    // - .class field: the declaring type of the member
    // - signatures: parameter types and return types (e.g., ICryptoTransform, CipherMode)
    {
        let view = assembly.view();
        if let Some(tables) = view.tables() {
            if let Some(memberref_table) = tables.table::<MemberRefRaw>() {
                for &memberref_rid in &deleted_memberref_rids {
                    if let Some(memberref) = memberref_table.get(memberref_rid).ok().flatten() {
                        if memberref.class.token.is_table(TableId::TypeRef) {
                            typeref_candidates.insert(memberref.class.token.row());
                        }
                    }
                }
            }
        }
    }

    // Add TypeRefs referenced through signatures of cascade-deleted MemberRefs
    typeref_candidates.extend(collect_typerefs_from_deleted_memberref_sigs(
        assembly,
        &deleted_memberref_rids,
    ));

    // Also include ALL non-deleted TypeRef RIDs
    {
        let view = assembly.view();
        if let Some(tables) = view.tables() {
            if let Some(typeref_table) = tables.table::<TypeRefRaw>() {
                for typeref in typeref_table {
                    let typeref = match typeref {
                        Ok(row) => row,
                        Err(e) => {
                            log::warn!("skipping unreadable metadata row: {e}");
                            continue;
                        }
                    };
                    if !assembly
                        .changes()
                        .is_row_deleted(TableId::TypeRef, typeref.rid)
                    {
                        typeref_candidates.insert(typeref.rid);
                    }
                }
            }
        }
    }

    let (typerefs_removed, deleted_typeref_rids) =
        remove_unreferenced_typerefs(assembly, &typeref_candidates, body_tokens);
    stats.add(TableId::TypeRef, typerefs_removed);

    // 8. Cascade to reference parents (ModuleRef, AssemblyRef).
    //    Candidates are resolution_scope of cascade-deleted TypeRefs
    //    and import_scope of deleted ImplMaps.
    let mut moduleref_candidates = BTreeSet::new();
    let mut assemblyref_candidates = BTreeSet::new();

    {
        let view = assembly.view();
        if let Some(tables) = view.tables() {
            // From cascade-deleted TypeRefs
            if let Some(typeref_table) = tables.table::<TypeRefRaw>() {
                for &typeref_rid in &deleted_typeref_rids {
                    if let Some(typeref) = typeref_table.get(typeref_rid).ok().flatten() {
                        match typeref.resolution_scope.tag {
                            TableId::AssemblyRef => {
                                assemblyref_candidates.insert(typeref.resolution_scope.row);
                            }
                            TableId::ModuleRef => {
                                moduleref_candidates.insert(typeref.resolution_scope.row);
                            }
                            _ => {}
                        }
                    }
                }
            }

            // From deleted ImplMaps (import_scope → ModuleRef)
            if let Some(implmap_table) = tables.table::<ImplMapRaw>() {
                for implmap in implmap_table {
                    let implmap = match implmap {
                        Ok(row) => row,
                        Err(e) => {
                            log::warn!("skipping unreadable metadata row: {e}");
                            continue;
                        }
                    };
                    if assembly
                        .changes()
                        .is_row_deleted(TableId::ImplMap, implmap.rid)
                    {
                        moduleref_candidates.insert(implmap.import_scope);
                    }
                }
            }
        }
    }

    // Also include ALL non-deleted ModuleRef/AssemblyRef RIDs
    {
        let view = assembly.view();
        if let Some(tables) = view.tables() {
            if let Some(table) = tables.table::<crate::metadata::tables::ModuleRefRaw>() {
                for row in table {
                    let row = match row {
                        Ok(row) => row,
                        Err(e) => {
                            log::warn!("skipping unreadable metadata row: {e}");
                            continue;
                        }
                    };
                    if !assembly
                        .changes()
                        .is_row_deleted(TableId::ModuleRef, row.rid)
                    {
                        moduleref_candidates.insert(row.rid);
                    }
                }
            }
            if let Some(table) = tables.table::<crate::metadata::tables::AssemblyRefRaw>() {
                for row in table {
                    let row = match row {
                        Ok(row) => row,
                        Err(e) => {
                            log::warn!("skipping unreadable metadata row: {e}");
                            continue;
                        }
                    };
                    if !assembly
                        .changes()
                        .is_row_deleted(TableId::AssemblyRef, row.rid)
                    {
                        assemblyref_candidates.insert(row.rid);
                    }
                }
            }
        }
    }

    stats.add(
        TableId::ModuleRef,
        remove_orphan_modulerefs(assembly, &moduleref_candidates),
    );
    stats.add(
        TableId::AssemblyRef,
        remove_orphan_assemblyrefs(assembly, &assemblyref_candidates),
    );

    // 9. Cascade to ExportedType, ManifestResource, and File.
    //    ExportedType/ManifestResource reference AssemblyRef and File.
    //    File entries are only removed if no surviving ExportedType or ManifestResource
    //    references them.
    let (exportedtypes_removed, deleted_exportedtype_rids) = remove_orphan_exportedtypes(assembly);
    stats.add(TableId::ExportedType, exportedtypes_removed);

    let (manifestresources_removed, deleted_manifestresource_rids) =
        remove_orphan_manifestresources(assembly);
    stats.add(TableId::ManifestResource, manifestresources_removed);

    // Collect File RID candidates from deleted ExportedType and ManifestResource entries
    let mut file_candidates = BTreeSet::new();
    {
        let view = assembly.view();
        if let Some(tables) = view.tables() {
            if let Some(table) = tables.table::<ExportedTypeRaw>() {
                for &rid in &deleted_exportedtype_rids {
                    if let Some(entry) = table.get(rid).ok().flatten() {
                        if entry.implementation.token.is_table(TableId::File) {
                            file_candidates.insert(entry.implementation.token.row());
                        }
                    }
                }
            }
            if let Some(table) = tables.table::<ManifestResourceRaw>() {
                for &rid in &deleted_manifestresource_rids {
                    if let Some(entry) = table.get(rid).ok().flatten() {
                        if entry.implementation.token.is_table(TableId::File) {
                            file_candidates.insert(entry.implementation.token.row());
                        }
                    }
                }
            }
        }
    }
    stats.add(
        TableId::File,
        remove_orphan_files(assembly, &file_candidates),
    );

    stats
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::{
        cilassembly::cleanup::orphans::DeletionContext,
        metadata::{tables::TableId, token::Token},
    };

    #[test]
    fn test_deletion_context_creation() {
        let types = HashSet::from([Token::from_parts(TableId::TypeDef, 1)]);
        let methods = HashSet::from([Token::from_parts(TableId::MethodDef, 2)]);
        let fields = HashSet::from([Token::from_parts(TableId::Field, 3)]);

        let ctx = DeletionContext::new(&types, &methods, &fields);

        assert!(ctx.is_type_deleted(Token::from_parts(TableId::TypeDef, 1)));
        assert!(ctx.is_method_deleted(Token::from_parts(TableId::MethodDef, 2)));
        assert!(ctx.is_field_deleted(Token::from_parts(TableId::Field, 3)));
        assert!(!ctx.is_type_deleted(Token::from_parts(TableId::TypeDef, 99)));
    }

    #[test]
    fn test_deletion_context_is_deleted() {
        let types = HashSet::from([Token::from_parts(TableId::TypeDef, 1)]);
        let empty_methods = HashSet::new();
        let empty_fields = HashSet::new();
        let ctx = DeletionContext::new(&types, &empty_methods, &empty_fields);

        assert!(ctx.is_deleted(Token::from_parts(TableId::TypeDef, 1)));
        assert!(!ctx.is_deleted(Token::from_parts(TableId::TypeDef, 2)));
    }
}

//! Reference scanning for orphan detection.
//!
//! This module provides functions to scan method bodies and metadata tables
//! to determine which entries (TypeRef, MemberRef, TypeSpec) are still
//! referenced and which can be safely removed.
//!
//! # Design
//!
//! Reference scanning is performed in two phases:
//!
//! 1. **Method body scanning**: Parses IL instructions in all method bodies
//!    (both original and regenerated) to collect token operands.
//!
//! 2. **Metadata table scanning**: Scans metadata tables that can reference
//!    TypeRefs, MemberRefs, and TypeSpecs (extends clauses, interfaces, etc.)
//!
//! # Regenerated Methods
//!
//! After SSA-based code optimization, method bodies may be regenerated with
//! different IL instructions. This module handles both:
//!
//! - **Original methods**: Read from the source file using their RVA
//! - **Regenerated methods**: Read from `CilAssembly.changes.method_bodies`
//!   (identified by placeholder RVAs >= 0xF000_0000)
//!
//! # Usage
//!
//! These functions are called from [`super::orphans`] to determine which
//! metadata entries can be removed without breaking the assembly.

use std::collections::{BTreeSet, HashSet};

use crate::{
    assembly::{decode_blocks, BasicBlock, Operand},
    cilassembly::{
        cleanup::utils::{
            extract_local_var_sig_rid, remove_candidates_not_alive, with_method_body,
        },
        modifications::TableModifications,
        operation::Operation,
        CilAssembly,
    },
    metadata::{
        method::{ExceptionHandlerFlags, MethodBody},
        signatures::{
            parse_field_signature, parse_local_var_signature, parse_method_signature,
            parse_method_spec_signature, parse_property_signature, parse_type_spec_signature,
            SIGNATURE_HEADER,
        },
        streams::Blob,
        tables::{
            skip_unreadable, CustomAttributeRaw, EventRaw, ExportedTypeRaw, FieldRaw,
            GenericParamConstraintRaw, ImplMapRaw, InterfaceImplRaw, ManifestResourceRaw,
            MemberRefRaw, MethodDefRaw, MethodImplRaw, MethodSpecRaw, PropertyRaw,
            StandAloneSigRaw, TableDataOwned, TableId, TypeDefRaw, TypeRefRaw, TypeSpecRaw,
        },
        token::Token,
    },
};

/// Pre-deletion reference data for cascade-based cleanup.
///
/// Collected **before** entities are deleted, this tracks what tokens the
/// entities being deleted currently reference. After deletion, only entries
/// that appear in this set AND are no longer referenced by surviving entities
/// are cascade-removed.
///
/// This approach is fundamentally safer than garbage-collection-style orphan
/// removal because it never removes pre-existing orphans (which may be used
/// via reflection or dynamic code generation).
pub(super) struct PreDeletionRefs {
    /// Token operands found in method bodies of entities being deleted.
    pub(super) il_tokens: HashSet<Token>,
    /// TypeRef RIDs referenced by signatures and extends clauses of entities being deleted.
    pub(super) typeref_rids: HashSet<u32>,
    /// StandAloneSig RIDs referenced by method bodies of methods being deleted.
    pub(super) standalonesig_rids: BTreeSet<u32>,
}

/// Collects all token references from entities that are about to be deleted.
///
/// Must be called **before** the entities are actually deleted, while their
/// method bodies, signatures, and metadata are still accessible.
///
/// # Arguments
///
/// * `assembly` - The assembly to scan
/// * `methods` - Method tokens that will be deleted
/// * `fields` - Field tokens that will be deleted
/// * `types` - Type tokens that will be deleted
///
/// # Returns
///
/// A [`PreDeletionRefs`] containing all tokens referenced by the entities.
pub(super) fn collect_pre_deletion_references(
    assembly: &CilAssembly,
    methods: &BTreeSet<Token>,
    fields: &BTreeSet<Token>,
    types: &BTreeSet<Token>,
) -> PreDeletionRefs {
    let mut il_tokens = HashSet::new();
    let mut typeref_rids = HashSet::new();
    let mut standalonesig_rids = BTreeSet::new();

    {
        let view = assembly.view();
        let Some(tables) = view.tables() else {
            return PreDeletionRefs {
                il_tokens,
                typeref_rids,
                standalonesig_rids,
            };
        };

        let blob_heap = view.blobs();

        // Scan method bodies and signatures of methods being deleted
        if let Some(methoddef_table) = tables.table::<MethodDefRaw>() {
            for methoddef in methoddef_table {
                let methoddef = match methoddef {
                    Ok(row) => row,
                    Err(e) => {
                        log::warn!("skipping unreadable metadata row: {e}");
                        continue;
                    }
                };
                let method_token = Token::from_parts(TableId::MethodDef, methoddef.rid);
                if !methods.contains(&method_token) {
                    continue;
                }

                // Get effective RVA (may be updated with placeholder if regenerated)
                let effective_rva =
                    get_effective_method_rva(assembly, methoddef.rid, methoddef.rva);
                if effective_rva == 0 {
                    continue;
                }

                // Scan method body IL for token operands and collect LocalVarSigTok
                with_method_body(assembly, effective_rva, &mut |data, base_rva| {
                    scan_method_body_bytes(data, base_rva, &mut il_tokens);
                    if let Some(sig_rid) = extract_local_var_sig_rid(data) {
                        standalonesig_rids.insert(sig_rid);
                    }
                });

                // Scan method signature for TypeRef references
                if let Some(blob) = &blob_heap {
                    scan_method_signature_blob(
                        blob,
                        methoddef.signature,
                        &mut TypeRefRows(&mut typeref_rids),
                    );
                }
            }
        }

        // Scan field signatures of fields being deleted
        if let Some(field_table) = tables.table::<FieldRaw>() {
            if let Some(blob) = &blob_heap {
                for field in field_table {
                    let field = match field {
                        Ok(row) => row,
                        Err(e) => {
                            log::warn!("skipping unreadable metadata row: {e}");
                            continue;
                        }
                    };
                    let field_token = Token::from_parts(TableId::Field, field.rid);
                    if !fields.contains(&field_token) {
                        continue;
                    }
                    scan_field_signature_blob(
                        blob,
                        field.signature,
                        &mut TypeRefRows(&mut typeref_rids),
                    );
                }
            }
        }

        // Scan extends clause of types being deleted
        if let Some(typedef_table) = tables.table::<TypeDefRaw>() {
            for type_token in types {
                if let Some(typedef) = typedef_table.get(type_token.row()).ok().flatten() {
                    if typedef.extends.token.is_table(TableId::TypeRef) {
                        typeref_rids.insert(typedef.extends.token.row());
                    }
                }
            }
        }

        // Scan CustomAttribute constructors whose parent is being deleted
        if let Some(attr_table) = tables.table::<CustomAttributeRaw>() {
            for attr in attr_table {
                let attr = match attr {
                    Ok(row) => row,
                    Err(e) => {
                        log::warn!("skipping unreadable metadata row: {e}");
                        continue;
                    }
                };
                let parent_token = attr.parent.token;
                let parent_deleted = types.contains(&parent_token)
                    || methods.contains(&parent_token)
                    || fields.contains(&parent_token);
                if !parent_deleted {
                    continue;
                }
                // The constructor may be a MemberRef or MethodDef
                il_tokens.insert(attr.constructor.token);
            }
        }
    }

    PreDeletionRefs {
        il_tokens,
        typeref_rids,
        standalonesig_rids,
    }
}

/// Gets the effective RVA for a MethodDef row, checking for updates.
///
/// If the MethodDef row has been updated (e.g., after code regeneration),
/// this returns the updated RVA from the operation. Otherwise returns the
/// original RVA from the table.
///
/// # Arguments
///
/// * `assembly` - The CilAssembly containing changes.
/// * `rid` - The MethodDef RID to look up.
/// * `original_rva` - The original RVA from the table.
///
/// # Returns
///
/// The effective RVA (updated if available, otherwise original).
fn get_effective_method_rva(assembly: &CilAssembly, rid: u32, original_rva: u32) -> u32 {
    // Check if there's an Update operation for this MethodDef
    if let Some(table_mods) = assembly.changes().table_changes.get(&TableId::MethodDef) {
        match table_mods {
            TableModifications::Sparse { operations, .. } => {
                // Search operations in reverse (most recent first) for this RID
                for op in operations.iter().rev() {
                    if op.get_rid() == rid {
                        match &op.operation {
                            Operation::Update(_, TableDataOwned::MethodDef(updated)) => {
                                return updated.rva;
                            }
                            Operation::Delete(_) => {
                                // Method was deleted, skip it
                                return 0;
                            }
                            _ => {}
                        }
                    }
                }
            }
            TableModifications::Replaced(rows) => {
                // Full replacement - find the row by index (RID - 1)
                if let Some(TableDataOwned::MethodDef(row)) =
                    rows.get(rid.saturating_sub(1) as usize)
                {
                    return row.rva;
                }
            }
        }
    }

    original_rva
}

/// Scans a method body's bytes and collects all referenced tokens.
///
/// This helper parses the method body header, decodes the IL instructions,
/// and extracts any token operands from the instructions.
///
/// # Arguments
///
/// * `data` - The method body bytes (starting with the header).
/// * `base_rva` - The RVA of the method body (used for relative addressing in IL).
/// * `referenced` - Output set to add discovered tokens to.
fn scan_method_body_bytes(data: &[u8], base_rva: usize, referenced: &mut HashSet<Token>) {
    let Ok(body) = MethodBody::from(data) else {
        return;
    };

    // Get the code bytes (after the header)
    let code_start = body.size_header;
    let Some(code_end) = code_start.checked_add(body.size_code) else {
        return;
    };
    if code_end > data.len() {
        return;
    }

    let Some(code_data) = data.get(code_start..code_end) else {
        return;
    };
    let Some(code_rva) = base_rva.checked_add(body.size_header) else {
        return;
    };

    // Helper: extract token operands from decoded blocks
    let collect = |blocks: &[BasicBlock], out: &mut HashSet<Token>| {
        for block in blocks {
            for instr in &block.instructions {
                if let Operand::Token(token) = instr.operand {
                    out.insert(token);
                }
            }
        }
    };

    // Decode main code flow
    if let Ok(blocks) = decode_blocks(code_data, 0, code_rva, None) {
        collect(&blocks, referenced);
    }

    // Decode exception handler and filter regions: these are not reachable via normal
    // control flow so decode_blocks(offset=0) never visits them. Use unbounded
    // recursive disassembly (None) so branch targets outside the handler's
    // declared region are followed (e.g., finally blocks that branch to
    // outlier code like Monitor.Exit or IDisposable.Dispose stubs).
    for handler in &body.exception_handlers {
        let mut entries = vec![handler.handler_offset as usize];
        if handler.flags == ExceptionHandlerFlags::FILTER {
            entries.push(handler.filter_offset as usize);
        }
        for entry in entries {
            if entry >= code_data.len() {
                continue;
            }
            let Some(entry_rva) = code_rva.checked_add(entry) else {
                continue;
            };
            if let Ok(blocks) = decode_blocks(code_data, entry, entry_rva, None) {
                collect(&blocks, referenced);
            }
        }

        // Catch clause class token (TypeDef/TypeRef/TypeSpec of the caught exception)
        if let Some(class_token) = handler.get_class_token() {
            referenced.insert(Token::new(class_token));
        }
    }
}

/// Collects TypeDef tokens referenced by surviving field signatures.
///
/// Scans the #Blob heap entries referenced by non-deleted Field rows,
/// parses them as field signatures, and extracts embedded TypeDef tokens.
/// This protects types like `__StaticArrayInitTypeSize=N` (which have no
/// methods, no fields, and are referenced only via field signature blobs)
/// from being incorrectly removed as "empty types".
pub(super) fn collect_typedefs_from_field_signatures(assembly: &CilAssembly) -> HashSet<Token> {
    let mut referenced = HashSet::new();

    let view = assembly.view();
    let Some(tables) = view.tables() else {
        return referenced;
    };
    let Some(field_table) = tables.table::<FieldRaw>() else {
        return referenced;
    };
    let Some(blob_heap) = view.blobs() else {
        return referenced;
    };

    for field in field_table.iter() {
        let field = match field {
            Ok(row) => row,
            Err(e) => {
                log::warn!("skipping unreadable metadata row: {e}");
                continue;
            }
        };
        if assembly.changes().is_row_deleted(TableId::Field, field.rid) {
            continue;
        }
        if let Ok(blob_data) = blob_heap.get(field.signature as usize) {
            if let Ok(sig) = parse_field_signature(blob_data) {
                sig.type_tokens(&mut referenced);
            }
        }
    }

    referenced
}

/// Collects TypeDef tokens referenced by surviving TypeSpec signatures.
///
/// A TypeSpec's signature names the types it is built from: the generic type
/// and its arguments for an instantiation, the element type for an array or
/// pointer, and so on. Those names can be TypeDefs of this assembly, and a
/// TypeSpec row is the only place they appear - no IL operand and no field
/// signature picks them up.
///
/// Without this, a TypeDef reachable only as, say, the argument of a
/// `List<T>` instantiation looks unused and is removed as an empty type,
/// leaving the surviving TypeSpec pointing at a row that is no longer there.
/// Loading the result then fails outright on the dangling spec.
///
/// This is the same protection [`collect_typedefs_from_field_signatures`]
/// gives to types named only by a field signature.
pub(super) fn collect_typedefs_from_typespec_signatures(assembly: &CilAssembly) -> HashSet<Token> {
    let mut referenced = HashSet::new();

    let view = assembly.view();
    let Some(tables) = view.tables() else {
        return referenced;
    };
    let Some(typespec_table) = tables.table::<TypeSpecRaw>() else {
        return referenced;
    };
    let Some(blob_heap) = view.blobs() else {
        return referenced;
    };

    for typespec in typespec_table.iter() {
        let typespec = match typespec {
            Ok(row) => row,
            Err(e) => {
                log::warn!("skipping unreadable metadata row: {e}");
                continue;
            }
        };
        if assembly
            .changes()
            .is_row_deleted(TableId::TypeSpec, typespec.rid)
        {
            continue;
        }
        if let Ok(blob_data) = blob_heap.get(typespec.signature as usize) {
            if let Ok(sig) = parse_type_spec_signature(blob_data) {
                sig.type_tokens(&mut referenced);
            }
        }
    }

    referenced
}

/// Collects the StandAloneSig RIDs surviving method bodies use: the LocalVarSigTok of each
/// fat header (original and regenerated bodies), and the `calli` operands among
/// `body_tokens`, whose StandAloneSig is a method signature.
pub(super) fn collect_referenced_standalonesig_rids(
    assembly: &CilAssembly,
    body_tokens: &HashSet<Token>,
) -> HashSet<u32> {
    let mut referenced = HashSet::new();

    // Collect (rid, rva) pairs while holding view borrow
    let method_rvas: Vec<u32> = {
        let view = assembly.view();
        let Some(tables) = view.tables() else {
            return referenced;
        };

        let Some(methoddef_table) = tables.table::<MethodDefRaw>() else {
            return referenced;
        };

        methoddef_table
            .into_iter()
            .filter_map(skip_unreadable)
            .filter(|m| !assembly.changes().is_row_deleted(TableId::MethodDef, m.rid))
            .map(|m| get_effective_method_rva(assembly, m.rid, m.rva))
            .filter(|&rva| rva != 0)
            .collect()
    };

    for effective_rva in method_rvas {
        with_method_body(assembly, effective_rva, &mut |data, _| {
            if let Some(sig_rid) = extract_local_var_sig_rid(data) {
                referenced.insert(sig_rid);
            }
        });
    }
    referenced.extend(rows_of(body_tokens, TableId::StandAloneSig));

    referenced
}

/// Scans all method bodies and collects tokens referenced from IL instructions.
///
/// This function handles both original method bodies (from the source file) and
/// regenerated method bodies (stored in AssemblyChanges after SSA optimization).
/// It checks for MethodDef row updates to get the correct RVA (placeholder for
/// regenerated methods, or original for unchanged methods).
///
/// Returns a set of all referenced tokens (TypeRef, TypeDef, MemberRef, MethodDef,
/// MethodSpec, TypeSpec, Field, etc.)
pub(super) fn scan_method_body_tokens(assembly: &CilAssembly) -> HashSet<Token> {
    let mut referenced = HashSet::new();

    // Collect (rid, effective_rva) pairs while holding view borrow
    let method_rvas: Vec<u32> = {
        let view = assembly.view();
        let Some(tables) = view.tables() else {
            return referenced;
        };

        let Some(methoddef_table) = tables.table::<MethodDefRaw>() else {
            return referenced;
        };

        methoddef_table
            .into_iter()
            .filter_map(skip_unreadable)
            .filter(|m| !assembly.changes().is_row_deleted(TableId::MethodDef, m.rid))
            .map(|m| get_effective_method_rva(assembly, m.rid, m.rva))
            .filter(|&rva| rva != 0)
            .collect()
    };

    // First pass: scan IL bytecode for token operands and collect local_var_sig RIDs.
    let mut local_sig_rids: HashSet<u32> = HashSet::new();
    for &effective_rva in &method_rvas {
        with_method_body(assembly, effective_rva, &mut |data, base_rva| {
            scan_method_body_bytes(data, base_rva, &mut referenced);
            // Also collect StandAloneSig RIDs from method body headers so we can
            // scan their blobs for embedded TypeDef/TypeRef tokens below.
            if let Ok(body) = MethodBody::from(data) {
                if body.local_var_sig_token != 0 {
                    local_sig_rids.insert(body.local_var_sig_token & 0x00FF_FFFF);
                }
            }
        });
    }

    // Second pass: scan the StandAloneSig blobs surviving methods use (local variable lists
    // and `calli` signatures) for the type tokens they embed. Without this, types referenced
    // only through those signatures (not via IL operands) would be unprotected from cleanup
    // removal.
    local_sig_rids.extend(rows_of(&referenced, TableId::StandAloneSig));
    {
        let view = assembly.view();
        if let (Some(tables), Some(blob_heap)) = (view.tables(), view.blobs()) {
            if let Some(sig_table) = tables.table::<StandAloneSigRaw>() {
                for &rid in &local_sig_rids {
                    if let Some(sig_row) = sig_table.get(rid).ok().flatten() {
                        if let Ok(blob_data) = blob_heap.get(sig_row.signature as usize) {
                            standalone_signature_type_tokens(blob_data, &mut referenced);
                        }
                    }
                }
            }
        }
    }

    referenced
}

/// Collects TypeRef RIDs referenced by the signatures of the given MemberRefs.
///
/// When MemberRefs are cascade-deleted, their `.class` TypeRefs become cascade
/// candidates. But TypeRefs referenced only through their **signatures** (parameter
/// types, return types) are not captured by the `.class` cascade. This function
/// fills that gap by scanning the signatures of deleted MemberRefs and returning
/// any TypeRef RIDs found within.
pub(super) fn collect_typerefs_from_deleted_memberref_sigs(
    assembly: &CilAssembly,
    memberref_rids: &HashSet<u32>,
) -> HashSet<u32> {
    let mut result = HashSet::new();

    if memberref_rids.is_empty() {
        return result;
    }

    let view = assembly.view();
    let Some(tables) = view.tables() else {
        return result;
    };
    let Some(blob_heap) = view.blobs() else {
        return result;
    };
    let Some(memberref_table) = tables.table::<MemberRefRaw>() else {
        return result;
    };

    for &rid in memberref_rids {
        if let Some(memberref) = memberref_table.get(rid).ok().flatten() {
            let mut rows = TypeRefRows(&mut result);
            if !scan_method_signature_blob(blob_heap, memberref.signature, &mut rows) {
                scan_field_signature_blob(blob_heap, memberref.signature, &mut rows);
            }
        }
    }

    result
}

/// The rows surviving metadata rows reference through a column that keeps its target alive.
///
/// These are every column of ECMA-335 II.22 that can name a TypeRef, TypeSpec, MemberRef,
/// ModuleRef, AssemblyRef or File:
///
/// | Column | Names |
/// |---|---|
/// | `TypeDef.Extends`, `InterfaceImpl.Interface`, `GenericParamConstraint.Constraint`, `Event.EventType` | TypeRef, TypeSpec |
/// | `MemberRef.Class` | TypeRef, TypeSpec, ModuleRef |
/// | `CustomAttribute.Type`, `MethodSpec.Method`, `MethodImpl.MethodBody`, `MethodImpl.MethodDeclaration` | MemberRef |
/// | `TypeRef.ResolutionScope` | ModuleRef, AssemblyRef |
/// | `ImplMap.ImportScope` | ModuleRef |
/// | `ExportedType.Implementation`, `ManifestResource.Implementation` | AssemblyRef, File |
///
/// The other columns that name these tables (`CustomAttribute.Parent`) belong to rows their
/// target owns, which go with it. A TypeRef's `ResolutionScope` naming another TypeRef is
/// nesting: [`close_over_typeref_nesting`] applies it once the live set is complete, so a
/// nested TypeRef on its way out does not keep its parent.
pub(super) fn scan_metadata_keepers(assembly: &CilAssembly) -> HashSet<Token> {
    let mut keepers = HashSet::new();
    let view = assembly.view();
    let Some(tables) = view.tables() else {
        return keepers;
    };
    let live = |table: TableId, rid: u32| !assembly.changes().is_row_deleted(table, rid);

    if let Some(table) = tables.table::<TypeDefRaw>() {
        for row in table.iter().filter_map(skip_unreadable) {
            if live(TableId::TypeDef, row.rid) {
                keepers.insert(row.extends.token);
            }
        }
    }
    if let Some(table) = tables.table::<InterfaceImplRaw>() {
        for row in table.iter().filter_map(skip_unreadable) {
            if live(TableId::InterfaceImpl, row.rid) {
                keepers.insert(row.interface.token);
            }
        }
    }
    if let Some(table) = tables.table::<GenericParamConstraintRaw>() {
        for row in table.iter().filter_map(skip_unreadable) {
            if live(TableId::GenericParamConstraint, row.rid) {
                keepers.insert(row.constraint.token);
            }
        }
    }
    if let Some(table) = tables.table::<EventRaw>() {
        for row in table.iter().filter_map(skip_unreadable) {
            if live(TableId::Event, row.rid) {
                keepers.insert(row.event_type.token);
            }
        }
    }
    if let Some(table) = tables.table::<MemberRefRaw>() {
        for row in table.iter().filter_map(skip_unreadable) {
            if live(TableId::MemberRef, row.rid) {
                keepers.insert(row.class.token);
            }
        }
    }
    if let Some(table) = tables.table::<CustomAttributeRaw>() {
        for row in table.iter().filter_map(skip_unreadable) {
            if live(TableId::CustomAttribute, row.rid) {
                keepers.insert(row.constructor.token);
            }
        }
    }
    if let Some(table) = tables.table::<MethodSpecRaw>() {
        for row in table.iter().filter_map(skip_unreadable) {
            if live(TableId::MethodSpec, row.rid) {
                keepers.insert(row.method.token);
            }
        }
    }
    if let Some(table) = tables.table::<MethodImplRaw>() {
        for row in table.iter().filter_map(skip_unreadable) {
            if live(TableId::MethodImpl, row.rid) {
                keepers.insert(row.method_body.token);
                keepers.insert(row.method_declaration.token);
            }
        }
    }
    if let Some(table) = tables.table::<TypeRefRaw>() {
        for row in table.iter().filter_map(skip_unreadable) {
            if live(TableId::TypeRef, row.rid)
                && !row.resolution_scope.token.is_table(TableId::TypeRef)
            {
                keepers.insert(row.resolution_scope.token);
            }
        }
    }
    if let Some(table) = tables.table::<ImplMapRaw>() {
        for row in table.iter().filter_map(skip_unreadable) {
            if live(TableId::ImplMap, row.rid) && row.import_scope != 0 {
                keepers.insert(Token::from_parts(TableId::ModuleRef, row.import_scope));
            }
        }
    }
    if let Some(table) = tables.table::<ExportedTypeRaw>() {
        for row in table.iter().filter_map(skip_unreadable) {
            if live(TableId::ExportedType, row.rid) {
                keepers.insert(row.implementation.token);
            }
        }
    }
    if let Some(table) = tables.table::<ManifestResourceRaw>() {
        for row in table.iter().filter_map(skip_unreadable) {
            if live(TableId::ManifestResource, row.rid) {
                keepers.insert(row.implementation.token);
            }
        }
    }

    keepers
}

/// The rows of `table` among `tokens`.
pub(super) fn rows_of(tokens: &HashSet<Token>, table: TableId) -> impl Iterator<Item = u32> + '_ {
    tokens
        .iter()
        .filter(move |token| token.is_table(table))
        .map(Token::row)
}

/// The `nested TypeRef -> enclosing TypeRef` edges, as `(rid, enclosing_rid)` pairs.
///
/// A nested type is encoded as a TypeRef whose `ResolutionScope` points at the *enclosing*
/// TypeRef. [`scan_metadata_keepers`] leaves that edge out: an enclosing TypeRef is kept only
/// through a nested TypeRef that is itself live, which only the complete live set tells.
///
/// Collected separately from [`close_over_typeref_nesting`] because the closure has to run
/// against the *complete* live set. Rows already marked deleted are excluded: a nested TypeRef
/// on its way out must not keep its parent alive.
fn typeref_nesting_edges(assembly: &CilAssembly) -> Vec<(u32, u32)> {
    let view = assembly.view();
    let Some(tables) = view.tables() else {
        return Vec::new();
    };
    let Some(typeref_table) = tables.table::<TypeRefRaw>() else {
        return Vec::new();
    };

    typeref_table
        .into_iter()
        .filter_map(skip_unreadable)
        .filter(|type_ref| {
            !assembly
                .changes()
                .is_row_deleted(TableId::TypeRef, type_ref.rid)
        })
        .filter(|type_ref| type_ref.resolution_scope.token.is_table(TableId::TypeRef))
        .map(|type_ref| (type_ref.rid, type_ref.resolution_scope.token.row()))
        .collect()
}

/// Marks every enclosing TypeRef of an already-live nested TypeRef live, transitively.
///
/// Must be called once the live set is **complete**. Running it earlier — while it could see
/// only the metadata-table references and not the IL body tokens, signature blobs, or
/// MemberRef-derived RIDs added afterwards — meant a nested TypeRef kept alive by an IL token
/// never marked its parent, which is the most common way a nested type stays live.
///
/// Nesting is transitive (`A+B+C`), so this iterates to a fixed point: marking `B` live must
/// in turn mark `A` live. Bounded by the edge count, since each pass either marks at least one
/// new RID live or stops.
fn close_over_typeref_nesting(referenced_rids: &mut HashSet<u32>, nesting: &[(u32, u32)]) {
    loop {
        let mut changed = false;
        for (rid, enclosing) in nesting {
            if referenced_rids.contains(rid) && referenced_rids.insert(*enclosing) {
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
}

/// The TypeRef rows among the tokens extended into it: a signature's
/// [`type_tokens`](crate::metadata::signatures::TypeSignature::type_tokens) collected as
/// TypeRef rows.
struct TypeRefRows<'a>(&'a mut HashSet<u32>);

impl Extend<Token> for TypeRefRows<'_> {
    fn extend<I: IntoIterator<Item = Token>>(&mut self, tokens: I) {
        self.0.extend(
            tokens
                .into_iter()
                .filter(|token| token.is_table(TableId::TypeRef))
                .map(|token| token.row()),
        );
    }
}

/// The TypeDef, TypeRef and TypeSpec tokens the signature blobs of surviving rows name.
///
/// This function scans signatures from:
/// - MethodDef.signature (method signatures)
/// - Field.signature (field signatures)
/// - MemberRef.signature (member reference signatures)
/// - StandAloneSig.signature, for the signatures surviving method bodies use: local variable
///   lists and `calli` method signatures
/// - TypeSpec.signature (type specification signatures)
/// - Property.type (property signatures)
/// - MethodSpec.instantiation (the type arguments of a generic method instantiation)
pub(super) fn scan_signature_type_refs(
    assembly: &CilAssembly,
    body_tokens: &HashSet<Token>,
) -> HashSet<Token> {
    let mut referenced_rids = HashSet::new();

    let view = assembly.view();
    let Some(tables) = view.tables() else {
        return referenced_rids;
    };

    let Some(blob_heap) = view.blobs() else {
        return referenced_rids;
    };

    // MethodDef signatures (skip deleted rows)
    if let Some(methoddef_table) = tables.table::<MethodDefRaw>() {
        for methoddef in methoddef_table {
            let methoddef = match methoddef {
                Ok(row) => row,
                Err(e) => {
                    log::warn!("skipping unreadable metadata row: {e}");
                    continue;
                }
            };
            if assembly
                .changes()
                .is_row_deleted(TableId::MethodDef, methoddef.rid)
            {
                continue;
            }
            scan_method_signature_blob(blob_heap, methoddef.signature, &mut referenced_rids);
        }
    }

    // Field signatures (skip deleted rows)
    if let Some(field_table) = tables.table::<FieldRaw>() {
        for field in field_table {
            let field = match field {
                Ok(row) => row,
                Err(e) => {
                    log::warn!("skipping unreadable metadata row: {e}");
                    continue;
                }
            };
            if assembly.changes().is_row_deleted(TableId::Field, field.rid) {
                continue;
            }
            scan_field_signature_blob(blob_heap, field.signature, &mut referenced_rids);
        }
    }

    // MemberRef signatures (skip deleted rows)
    if let Some(memberref_table) = tables.table::<MemberRefRaw>() {
        for memberref in memberref_table {
            let memberref = match memberref {
                Ok(row) => row,
                Err(e) => {
                    log::warn!("skipping unreadable metadata row: {e}");
                    continue;
                }
            };
            if assembly
                .changes()
                .is_row_deleted(TableId::MemberRef, memberref.rid)
            {
                continue;
            }
            // MemberRef can have either method or field signature
            // Try method first (more common), then field
            if !scan_method_signature_blob(blob_heap, memberref.signature, &mut referenced_rids) {
                scan_field_signature_blob(blob_heap, memberref.signature, &mut referenced_rids);
            }
        }
    }

    // StandAloneSig signatures - only scan those actually referenced by method bodies.
    // Regenerated methods may not use their original signatures.
    let referenced_sigs = collect_referenced_standalonesig_rids(assembly, body_tokens);
    if let Some(standalonesig_table) = tables.table::<StandAloneSigRaw>() {
        for sig in standalonesig_table {
            let sig = match sig {
                Ok(row) => row,
                Err(e) => {
                    log::warn!("skipping unreadable metadata row: {e}");
                    continue;
                }
            };
            // Only scan StandAloneSigs that are referenced by current method bodies
            if referenced_sigs.contains(&sig.rid) {
                if let Ok(blob_data) = blob_heap.get(sig.signature as usize) {
                    standalone_signature_type_tokens(blob_data, &mut referenced_rids);
                }
            }
        }
    }

    // TypeSpec signatures (skip deleted rows)
    if let Some(typespec_table) = tables.table::<TypeSpecRaw>() {
        for typespec in typespec_table {
            let typespec = match typespec {
                Ok(row) => row,
                Err(e) => {
                    log::warn!("skipping unreadable metadata row: {e}");
                    continue;
                }
            };
            if assembly
                .changes()
                .is_row_deleted(TableId::TypeSpec, typespec.rid)
            {
                continue;
            }
            scan_typespec_signature_blob(blob_heap, typespec.signature, &mut referenced_rids);
        }
    }

    // Property signatures (skip deleted rows)
    if let Some(property_table) = tables.table::<PropertyRaw>() {
        for property in property_table {
            let property = match property {
                Ok(row) => row,
                Err(e) => {
                    log::warn!("skipping unreadable metadata row: {e}");
                    continue;
                }
            };
            if assembly
                .changes()
                .is_row_deleted(TableId::Property, property.rid)
            {
                continue;
            }
            scan_property_signature_blob(blob_heap, property.signature, &mut referenced_rids);
        }
    }

    // MethodSpec instantiations (skip deleted rows)
    if let Some(methodspec_table) = tables.table::<MethodSpecRaw>() {
        for spec in methodspec_table.iter().filter_map(skip_unreadable) {
            if assembly
                .changes()
                .is_row_deleted(TableId::MethodSpec, spec.rid)
            {
                continue;
            }
            let Ok(blob_data) = blob_heap.get(spec.instantiation as usize) else {
                continue;
            };
            if let Ok(instantiation) = parse_method_spec_signature(blob_data) {
                instantiation.type_tokens(&mut referenced_rids);
            }
        }
    }

    referenced_rids
}

/// Scans a method signature blob for TypeRef references.
/// Returns true if the blob was successfully parsed as a method signature.
fn scan_method_signature_blob(
    blob_heap: &Blob<'_>,
    blob_index: u32,
    referenced: &mut impl Extend<Token>,
) -> bool {
    let Ok(blob_data) = blob_heap.get(blob_index as usize) else {
        return false;
    };

    let Ok(sig) = parse_method_signature(blob_data) else {
        return false;
    };

    sig.type_tokens(referenced);

    true
}

/// Scans a field signature blob for TypeRef references.
/// Returns true if the blob was successfully parsed as a field signature.
fn scan_field_signature_blob(
    blob_heap: &Blob<'_>,
    blob_index: u32,
    referenced: &mut impl Extend<Token>,
) -> bool {
    let Ok(blob_data) = blob_heap.get(blob_index as usize) else {
        return false;
    };

    let Ok(sig) = parse_field_signature(blob_data) else {
        return false;
    };

    sig.type_tokens(referenced);

    true
}

/// The type tokens a StandAloneSig blob names: a local variable list (`LOCAL_SIG`) or, for a
/// `calli`, a method signature.
fn standalone_signature_type_tokens(blob_data: &[u8], referenced: &mut impl Extend<Token>) {
    if blob_data.first() == Some(&SIGNATURE_HEADER::LOCAL_SIG) {
        if let Ok(sig) = parse_local_var_signature(blob_data) {
            sig.type_tokens(referenced);
        }
    } else if let Ok(sig) = parse_method_signature(blob_data) {
        sig.type_tokens(referenced);
    }
}

/// Scans a TypeSpec signature blob for TypeRef references.
fn scan_typespec_signature_blob(
    blob_heap: &Blob<'_>,
    blob_index: u32,
    referenced: &mut impl Extend<Token>,
) {
    let Ok(blob_data) = blob_heap.get(blob_index as usize) else {
        return;
    };

    let Ok(sig) = parse_type_spec_signature(blob_data) else {
        return;
    };

    sig.type_tokens(referenced);
}

/// Scans a property signature blob for TypeRef references.
fn scan_property_signature_blob(
    blob_heap: &Blob<'_>,
    blob_index: u32,
    referenced: &mut impl Extend<Token>,
) {
    let Ok(blob_data) = blob_heap.get(blob_index as usize) else {
        return;
    };

    let Ok(sig) = parse_property_signature(blob_data) else {
        return;
    };

    sig.type_tokens(referenced);
}

/// Removes TypeRef entries that are cascade candidates and no longer referenced.
///
/// Only removes TypeRefs that are in the `candidates` set AND are not referenced
/// by any surviving code or metadata. This is the cascade-safe version that
/// preserves pre-existing orphans.
///
/// # Returns
///
/// A tuple of (count_removed, set_of_deleted_rids).
pub(super) fn remove_unreferenced_typerefs(
    assembly: &mut CilAssembly,
    candidates: &BTreeSet<u32>,
    body_tokens: &HashSet<Token>,
) -> (usize, HashSet<u32>) {
    if candidates.is_empty() {
        return (0, HashSet::new());
    }

    // Collect all referenced TypeRef RIDs (live set from surviving entities)
    let mut referenced_rids = HashSet::new();

    // From method bodies (IL token operands)
    for token in body_tokens {
        if token.is_table(TableId::TypeRef) {
            referenced_rids.insert(token.row());
        }
    }

    // From the metadata columns and signature blobs of surviving rows, at this point, after
    // prior cascade removals. A surviving MemberRef's class is among the columns, so the
    // TypeRefs of the MemberRefs code and attributes still use are kept.
    referenced_rids.extend(rows_of(&scan_metadata_keepers(assembly), TableId::TypeRef));
    referenced_rids.extend(rows_of(
        &scan_signature_type_refs(assembly, body_tokens),
        TableId::TypeRef,
    ));

    // Last, once every source above has contributed: a nested TypeRef that survives keeps its
    // enclosing TypeRef alive. This has to see the whole live set, so that a nested TypeRef
    // kept alive by an IL body token, a signature blob or a MemberRef marks its parent too.
    let nesting = typeref_nesting_edges(assembly);
    close_over_typeref_nesting(&mut referenced_rids, &nesting);

    remove_candidates_not_alive(assembly, TableId::TypeRef, candidates, &referenced_rids)
}

/// Removes MemberRef entries that are cascade candidates and no longer referenced.
///
/// Only removes MemberRefs that are in the `candidates` set AND are not referenced
/// by any surviving code or metadata.
///
/// # Returns
///
/// A tuple of (count_removed, set_of_deleted_rids).
pub(super) fn remove_unreferenced_memberrefs(
    assembly: &mut CilAssembly,
    candidates: &BTreeSet<u32>,
    body_tokens: &HashSet<Token>,
) -> (usize, HashSet<u32>) {
    if candidates.is_empty() {
        return (0, HashSet::new());
    }

    // Collect all referenced MemberRef RIDs (live set)
    let mut referenced_rids = HashSet::new();

    // From method bodies
    for token in body_tokens {
        if token.is_table(TableId::MemberRef) {
            referenced_rids.insert(token.row());
        }
    }

    // From the metadata columns of surviving rows, reflecting the current deletion state:
    // custom attribute constructors, MethodSpecs and MethodImpls.
    referenced_rids.extend(rows_of(
        &scan_metadata_keepers(assembly),
        TableId::MemberRef,
    ));

    remove_candidates_not_alive(assembly, TableId::MemberRef, candidates, &referenced_rids)
}

/// Removes TypeSpec entries that are cascade candidates and no longer referenced.
///
/// Only removes TypeSpecs that are in the `candidates` set AND are not referenced
/// by any surviving code or metadata.
///
/// # Returns
///
/// A tuple of (count_removed, set_of_deleted_rids).
pub(super) fn remove_unreferenced_typespecs(
    assembly: &mut CilAssembly,
    candidates: &BTreeSet<u32>,
    body_tokens: &HashSet<Token>,
) -> (usize, HashSet<u32>) {
    if candidates.is_empty() {
        return (0, HashSet::new());
    }

    // Collect all referenced TypeSpec RIDs (live set)
    let mut referenced_rids = HashSet::new();

    // From method bodies
    for token in body_tokens {
        if token.is_table(TableId::TypeSpec) {
            referenced_rids.insert(token.row());
        }
    }

    // From the metadata columns and signature blobs of surviving rows, at this point, after
    // prior cascade removals.
    referenced_rids.extend(rows_of(&scan_metadata_keepers(assembly), TableId::TypeSpec));
    referenced_rids.extend(rows_of(
        &scan_signature_type_refs(assembly, body_tokens),
        TableId::TypeSpec,
    ));

    remove_candidates_not_alive(assembly, TableId::TypeSpec, candidates, &referenced_rids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::changes::METHOD_BODY_PLACEHOLDER_BASE,
        metadata::{tables::TableId, token::Token},
    };

    #[test]
    fn test_placeholder_rva_detection() {
        // Placeholder RVAs start at 0xF000_0000
        const { assert!(0xF000_0000 >= METHOD_BODY_PLACEHOLDER_BASE) };
        const { assert!(0xF000_0001 >= METHOD_BODY_PLACEHOLDER_BASE) };

        // Normal RVAs are below the threshold
        const { assert!(0x2000 < METHOD_BODY_PLACEHOLDER_BASE) };
        const { assert!(0x0000_FFFF < METHOD_BODY_PLACEHOLDER_BASE) };
    }

    #[test]
    fn test_token_table_detection() {
        let typeref_token = Token::new(0x01000005);
        let memberref_token = Token::new(0x0A000010);
        let typespec_token = Token::new(0x1B000003);

        assert!(typeref_token.is_table(TableId::TypeRef));
        assert!(memberref_token.is_table(TableId::MemberRef));
        assert!(typespec_token.is_table(TableId::TypeSpec));
    }

    /// A nested TypeRef kept alive by *any* source must keep its enclosing TypeRef alive too.
    ///
    /// The live set is seeded with a RID only an IL body token supplied: the closure runs over
    /// the complete live set, so the enclosing RIDs are marked, and the survivor's
    /// `ResolutionScope` never points at a deleted row.
    #[test]
    fn nesting_closure_marks_enclosing_typerefs_of_a_live_nested_typeref() {
        // 3 nested in 2, 2 nested in 1 — the transitive `A+B+C` shape.
        let nesting = [(3u32, 2u32), (2u32, 1u32)];

        // RID 3 is live only because an IL body token referenced it.
        let mut live = HashSet::from([3u32]);
        close_over_typeref_nesting(&mut live, &nesting);

        assert!(live.contains(&2), "the immediately enclosing TypeRef");
        assert!(
            live.contains(&1),
            "nesting is transitive, so the outermost TypeRef must be marked too"
        );
    }

    /// The closure must not resurrect an enclosing TypeRef whose nested type is itself dead.
    #[test]
    fn nesting_closure_leaves_unreferenced_chains_alone() {
        let nesting = [(3u32, 2u32), (2u32, 1u32)];

        let mut live = HashSet::from([9u32]);
        close_over_typeref_nesting(&mut live, &nesting);

        assert_eq!(live, HashSet::from([9u32]));
    }

    /// A cycle in `ResolutionScope` must not spin: the fixed point stops once nothing new is
    /// marked, so a self- or mutually-nested pair terminates rather than looping forever.
    #[test]
    fn nesting_closure_terminates_on_a_cycle() {
        let nesting = [(1u32, 2u32), (2u32, 1u32)];

        let mut live = HashSet::from([1u32]);
        close_over_typeref_nesting(&mut live, &nesting);

        assert_eq!(live, HashSet::from([1u32, 2u32]));
    }
}

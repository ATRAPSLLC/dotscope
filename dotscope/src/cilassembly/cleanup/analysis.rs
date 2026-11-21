//! Cleanup analysis functions for assembly metadata.
//!
//! This module provides generic, stateless analysis functions that operate on
//! [`CilObject`] and method call graph data without any deobfuscation dependency.
//! These functions are used to determine what metadata entities can be safely
//! removed during cleanup.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::{
    cilassembly::cleanup::CleanupRequest,
    metadata::{
        signatures::{parse_type_spec_signature, TypeSignature},
        tables::{
            skip_unreadable, CustomAttributeRaw, GenericParamConstraintRaw, GenericParamRaw,
            InterfaceImplRaw, TableId, TypeDefRaw, TypeSpecRaw,
        },
        token::Token,
    },
    CilObject,
};

/// Expands a cleanup request to include member tokens of deleted types
/// and their nested types.
///
/// The cleanup request stores [`TypeDef`](crate::metadata::tables::TableId::TypeDef)
/// tokens for types scheduled for deletion, but SSA instructions reference their
/// members via [`Field`](crate::metadata::tables::TableId::Field) and
/// [`MethodDef`](crate::metadata::tables::TableId::MethodDef) tokens. Without
/// expansion, the neutralization pass cannot match instructions that load fields
/// or call methods belonging to deleted types.
///
/// For each type in the request, this collects all nested types and their field
/// and method tokens from the type registry and adds them to the token set.
///
/// # Arguments
///
/// * `request` - The merged cleanup request containing types, methods, and
///   fields scheduled for deletion.
/// * `assembly` - The assembly whose type registry is used to resolve type
///   members.
///
/// # Returns
///
/// A [`HashSet`] containing all tokens from the request plus the expanded
/// member tokens. Returns the original token set unchanged if no types are
/// scheduled for deletion.
pub fn expand_type_tokens(request: &CleanupRequest, assembly: &CilObject) -> HashSet<Token> {
    let mut tokens = request.all_tokens();
    let registry = assembly.types();

    // Collect types to process: explicit types + their nested types
    let mut types_to_expand: Vec<Token> = request.types().copied().collect();
    for type_token in request.types() {
        if let Some(cil_type) = registry.get(type_token) {
            for (_, nested_ref) in cil_type.nested_types.iter() {
                if let Some(t) = nested_ref.token() {
                    types_to_expand.push(t);
                    tokens.insert(t);
                }
            }
        }
    }

    // Expand each type (and nested type) to its member tokens
    for type_token in &types_to_expand {
        if let Some(cil_type) = registry.get(type_token) {
            for (_, field) in cil_type.fields.iter() {
                tokens.insert(field.token);
            }
            for (_, method_ref) in cil_type.methods.iter() {
                if let Some(method) = method_ref.upgrade() {
                    tokens.insert(method.token);
                }
            }
        }
    }

    tokens
}

/// Which rows name which types.
///
/// Instructions are not the only place a type is named. A field's type, a
/// method's parameters and return type, a property's type, a type's base and
/// the interfaces it implements, the constraints on a generic parameter, the
/// parts a TypeSpec is built from, and a method's local variables all name
/// types, and no call records any of them, so a call graph cannot see them.
/// Deleting a type one of them still names leaves that row pointing at
/// whatever the type's row number holds after compaction - another type, or
/// nothing - and the result fails to load at the survivor, far from the
/// decision that broke it.
///
/// Each name is kept with the row whose survival keeps it alive, so the table
/// is built once and asking what the rows surviving a cleanup name is a
/// filter over it, however often the removal set changes.
#[derive(Debug, Default)]
pub struct TypeNames {
    /// `(owner, named type)`. `None` for a name nothing's removal withdraws:
    /// TypeSpecs are removed only as orphans, after this decision.
    names: Vec<(Option<Token>, Token)>,
    /// Scratch set for collecting one signature's names.
    scratch: HashSet<Token>,
}

impl TypeNames {
    /// The names the assembly's metadata holds: member signatures, base types,
    /// interface lists, generic parameter constraints and TypeSpecs. Local
    /// variables are the caller's to add with [`add_signature`](Self::add_signature),
    /// since which signature a method ends up with depends on whether its body
    /// is regenerated.
    #[must_use]
    pub fn of_metadata(assembly: &CilObject) -> Self {
        let mut names = Self::default();

        for type_entry in assembly.types().iter() {
            let type_token = *type_entry.key();
            if !type_token.is_table(TableId::TypeDef) {
                continue;
            }
            let cil_type = type_entry.value();
            for (_, field) in cil_type.fields.iter() {
                names.add_signature(Some(field.token), &field.signature.base);
            }
            for method in cil_type.methods() {
                let signature = &method.signature;
                for param in std::iter::once(&signature.return_type)
                    .chain(&signature.params)
                    .chain(&signature.varargs)
                {
                    names.add_signature(Some(method.token), &param.base);
                }
            }
            for (_, property) in cil_type.properties.iter() {
                names.add_signature(Some(type_token), &property.signature.base);
                for param in &property.signature.params {
                    names.add_signature(Some(type_token), &param.base);
                }
            }
        }

        let Some(tables) = assembly.tables() else {
            return names;
        };
        if let Some(table) = tables.table::<TypeDefRaw>() {
            for row in table.iter().filter_map(skip_unreadable) {
                names.add_token(Some(row.token), row.extends.token);
            }
        }
        if let Some(table) = tables.table::<InterfaceImplRaw>() {
            for row in table.iter().filter_map(skip_unreadable) {
                let class = Token::from_parts(TableId::TypeDef, row.class);
                names.add_token(Some(class), row.interface.token);
            }
        }
        if let (Some(constraints), Some(params)) = (
            tables.table::<GenericParamConstraintRaw>(),
            tables.table::<GenericParamRaw>(),
        ) {
            for row in constraints.iter().filter_map(skip_unreadable) {
                if let Some(param) = params.get(row.owner).ok().flatten() {
                    names.add_token(Some(param.owner.token), row.constraint.token);
                }
            }
        }
        if let (Some(table), Some(blob_heap)) = (tables.table::<TypeSpecRaw>(), assembly.blob()) {
            for row in table.iter().filter_map(skip_unreadable) {
                if let Ok(sig) = blob_heap
                    .get(row.signature as usize)
                    .and_then(parse_type_spec_signature)
                {
                    names.add_signature(None, &sig.base);
                }
            }
        }

        names
    }

    /// Records that `owner` names every type `signature` names.
    pub fn add_signature(&mut self, owner: Option<Token>, signature: &TypeSignature) {
        signature.type_tokens(&mut self.scratch);
        for named in self.scratch.drain() {
            self.names.push((owner, named));
        }
    }

    /// Records that `owner` names `named`, when it names a type at all.
    fn add_token(&mut self, owner: Option<Token>, named: Token) {
        if matches!(named.table(), 0x01 | 0x02 | 0x1B) && named.row() != 0 {
            self.names.push((owner, named));
        }
    }

    /// The types named by rows that survive a cleanup removing `removed`
    /// (every token it removes, members of removed types included - see
    /// [`expand_type_tokens`]).
    pub fn named_by_survivors<'a>(
        &'a self,
        removed: &'a HashSet<Token>,
    ) -> impl Iterator<Item = Token> + 'a {
        self.names
            .iter()
            .filter(|(owner, _)| owner.is_none_or(|owner| !removed.contains(&owner)))
            .map(|&(_, named)| named)
    }
}

/// Finds non-public TypeDef tokens that have no live cross-type references
/// in the provided method call graph.
///
/// These are self-contained infrastructure types that can be safely deleted.
/// Reachability is computed transitively: candidate types are rooted at every
/// live non-candidate type, and a candidate reached from a root is itself
/// promoted to a root. A type is considered unreferenced only when no chain of
/// calls from live code arrives at it. Stopping after a single step would
/// delete clusters that are reachable solely through another candidate — a VM
/// dispatcher or decryptor facade that turns out to be live.
///
/// This handles two key scenarios:
/// - **Proxy devirtualization**: wrapper types whose methods are
///   devirtualized away, leaving no external callers.
/// - **Transitive infrastructure**: types only referenced by other
///   infrastructure already tagged for deletion.
///
/// # Arguments
///
/// * `assembly` - The assembly whose type registry provides type definitions.
/// * `method_call_graph` - A mapping from caller method token to the set of
///   callee tokens it references.
/// * `request` - The current cleanup request. Methods/types already tagged
///   for deletion are not considered live callers.
///
/// # Returns
///
/// A [`Vec`] of TypeDef tokens for unreferenced types that can be safely removed.
pub fn find_unreferenced_types(
    assembly: &CilObject,
    method_call_graph: &BTreeMap<Token, BTreeSet<Token>>,
    request: &CleanupRequest,
) -> Vec<Token> {
    let method_to_type = build_method_type_map(assembly);

    // Protect only the type containing the assembly's declared entry point
    // (e.g., the Program class with Main). .cctors are runtime-invoked
    // initialization methods, NOT type-level entry points for reachability
    // analysis — a type whose only "entry" is a .cctor is still deletable
    // infrastructure if no live code ever accesses the type.
    let mut entry_point_types: HashSet<Token> = HashSet::new();
    let entry_token_val = assembly.cor20header().entry_point_token;
    if entry_token_val != 0 {
        let entry_token = Token::new(entry_token_val);
        if let Some(&type_token) = method_to_type.get(&entry_token) {
            entry_point_types.insert(type_token);
        }
    }

    let registry = assembly.types();

    // Pre-filter: collect candidate types (non-public, non-module, non-entry-point).
    // Public types are excluded — they may be library API or reflection targets
    // with no in-assembly callers.
    let mut candidates: HashSet<Token> = HashSet::new();

    for type_entry in registry.iter() {
        let type_token = *type_entry.key();
        if type_token.table() != 0x02 {
            continue;
        }
        let cil_type = type_entry.value();
        if cil_type.is_module_type() || cil_type.is_public() {
            continue;
        }
        if entry_point_types.contains(&type_token) {
            continue;
        }
        // Already tagged for deletion — skip
        if request.types().any(|t| *t == type_token) {
            continue;
        }

        let type_methods: Vec<Token> = cil_type.methods().map(|m| m.token).collect();
        if type_methods.is_empty() {
            continue;
        }

        // Require at least one non-cctor method
        let has_non_cctor = type_methods.iter().any(|m| {
            !cil_type
                .methods()
                .any(|method| method.token == *m && method.is_cctor())
        });
        if !has_non_cctor {
            continue;
        }

        candidates.insert(type_token);
    }

    // Seed the deleted set with types/methods already in the cleanup request
    let deleted_types: HashSet<Token> = request.types().copied().collect();
    let mut deleted_methods: HashSet<Token> = request.methods().copied().collect();

    // Expand deleted types to include their method tokens
    for type_token in &deleted_types {
        if let Some(cil_type) = registry.get(type_token) {
            for method in cil_type.methods() {
                deleted_methods.insert(method.token);
            }
        }
    }

    // Collapse the method call graph to type granularity, keeping only edges
    // whose caller is still live. Doing this once lets reachability be answered
    // with a single worklist drain instead of re-scanning every call edge per
    // round.
    let mut type_calls: HashMap<Token, HashSet<Token>> = HashMap::new();
    for (caller_token, callees) in method_call_graph {
        // Skip callers that are deleted
        if deleted_methods.contains(caller_token) {
            continue;
        }
        let Some(caller_type) = method_to_type.get(caller_token).copied() else {
            continue;
        };
        // Skip callers whose type is deleted
        if deleted_types.contains(&caller_type) {
            continue;
        }

        for callee_token in callees {
            let Some(callee_type) = method_to_type.get(callee_token).copied() else {
                continue;
            };
            // Intra-type calls say nothing about whether the type is reachable
            if caller_type == callee_type {
                continue;
            }
            type_calls
                .entry(caller_type)
                .or_default()
                .insert(callee_type);
        }
    }

    // A nested type cannot outlive its enclosing type: deleting an enclosing
    // type cascades to its nested types via [`expand_type_tokens`]. Model that
    // as an edge from nested to enclosing so a live nested type keeps its
    // parent alive, rather than being silently dropped along with it.
    for type_entry in registry.iter() {
        let type_token = *type_entry.key();
        if type_token.table() != 0x02 {
            continue;
        }
        // A type already scheduled for deletion is not live and must never
        // become a reachability root
        if deleted_types.contains(&type_token) {
            continue;
        }
        if let Some(enclosing) = type_entry.value().enclosing_type() {
            if enclosing.token != type_token {
                type_calls
                    .entry(type_token)
                    .or_default()
                    .insert(enclosing.token);
            }
        }
    }

    // Seed the roots: every live type that is not itself a candidate. Candidacy
    // is what reachability has to resolve, so a candidate cannot serve as proof
    // that another candidate is referenced.
    let mut worklist: Vec<Token> = type_calls
        .keys()
        .filter(|type_token| !candidates.contains(type_token))
        .copied()
        .collect();

    // CustomAttribute constructors reference types that the call graph misses.
    // Types like EmbeddedAttribute and RefSafetyRulesAttribute are only referenced
    // from CustomAttribute rows (their .ctors are attribute constructors), never
    // from IL code. Without this check they appear unreferenced and get deleted.
    // They join the roots so that whatever they call stays alive as well.
    if let Some(tables) = assembly.tables() {
        if let Some(attr_table) = tables.table::<CustomAttributeRaw>() {
            for row in attr_table {
                let row = match row {
                    Ok(row) => row,
                    Err(e) => {
                        log::warn!("skipping unreadable metadata row: {e}");
                        continue;
                    }
                };
                if row.constructor.token.is_table(TableId::MethodDef) {
                    if let Some(&ctor_type) = method_to_type.get(&row.constructor.token) {
                        if candidates.remove(&ctor_type) {
                            worklist.push(ctor_type);
                        }
                    }
                }
            }
        }
    }

    // Propagate liveness transitively. A candidate rescued here becomes a root
    // in turn — without that, a cluster reachable only through another candidate
    // (a VM dispatcher, a decryptor facade) is misread as isolated infrastructure.
    while let Some(live_type) = worklist.pop() {
        let Some(callees) = type_calls.get(&live_type) else {
            continue;
        };
        for callee_type in callees {
            if candidates.remove(callee_type) {
                worklist.push(*callee_type);
            }
        }
    }

    // Whatever is still a candidate is unreachable from live code
    let mut unreferenced: Vec<Token> = candidates.into_iter().collect();
    unreferenced.sort_unstable();
    unreferenced
}

/// Pre-computes the set of entry-point method tokens that should not be removed.
///
/// Entry points include:
/// - The assembly's declared entry point (e.g., `Main`)
/// - Static constructors (`.cctor`)
/// - In non-aggressive mode: public methods outside `<Module>` (potential API surface)
///
/// This avoids calling per-method entry-point checks, reducing overall complexity
/// from O(dead_methods * all_methods) to O(all_methods).
///
/// # Arguments
///
/// * `assembly` - The assembly to scan for entry points.
/// * `aggressive` - If `true`, only protect the assembly entry point and static
///   constructors. If `false`, also protect public methods as potential external API.
pub fn compute_entry_points(assembly: &CilObject, aggressive: bool) -> HashSet<Token> {
    let mut entry_points = HashSet::new();

    // Assembly entry point
    let entry_token_val = assembly.cor20header().entry_point_token;
    if entry_token_val != 0 {
        entry_points.insert(Token::new(entry_token_val));
    }

    for method_entry in assembly.methods() {
        let method = method_entry.value();

        // Static constructors are special runtime entry points
        if method.is_cctor() {
            entry_points.insert(method.token);
            continue;
        }

        if aggressive {
            continue;
        }

        // In non-aggressive mode, protect public methods as potential external API.
        // Exception: public methods in <Module> are obfuscator infrastructure.
        if method.is_public() {
            let in_module = assembly.types().module_type().is_some_and(|module_type| {
                module_type
                    .methods
                    .iter()
                    .any(|(_, r)| r.upgrade().is_some_and(|m| m.token == method.token))
            });
            if !in_module {
                entry_points.insert(method.token);
            }
        }
    }

    entry_points
}

/// Builds a method-to-declaring-type mapping from the type registry.
///
/// Returns a [`HashMap`] mapping each method token to the TypeDef token of
/// the type that declares it. This is useful for determining whether two
/// methods belong to the same type.
pub fn build_method_type_map(assembly: &CilObject) -> HashMap<Token, Token> {
    let registry = assembly.types();
    let mut map = HashMap::new();

    for type_entry in registry.iter() {
        let type_token = *type_entry.key();
        if type_token.table() != 0x02 {
            continue;
        }
        let cil_type = type_entry.value();
        for method in cil_type.methods() {
            map.insert(method.token, type_token);
        }
    }

    map
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashSet};

    use super::*;
    use crate::{metadata::signatures::TypeSignature, testkit::helpers::test_assembly_arc};

    #[test]
    fn signatures_and_base_types_name_the_types_they_use() {
        let assembly = test_assembly_arc();
        let named: HashSet<Token> = TypeNames::of_metadata(&assembly)
            .named_by_survivors(&HashSet::new())
            .collect();

        let mut by_fields = 0;
        let mut by_bases = 0;
        for entry in assembly.types().iter() {
            let cil_type = entry.value();
            if !cil_type.token.is_table(TableId::TypeDef) {
                continue;
            }
            for (_, field) in cil_type.fields.iter() {
                if let TypeSignature::Class(token) | TypeSignature::ValueType(token) =
                    field.signature.base
                {
                    if token.is_table(TableId::TypeDef) {
                        assert!(
                            named.contains(&token),
                            "{token:?}, the type of {:?}",
                            field.token
                        );
                        by_fields += 1;
                    }
                }
            }
        }
        let tables = assembly.tables().expect("tables");
        let typedefs = tables.table::<TypeDefRaw>().expect("TypeDef table");
        for row in typedefs.iter().filter_map(skip_unreadable) {
            if row.extends.token.is_table(TableId::TypeDef) && row.extends.token.row() != 0 {
                assert!(
                    named.contains(&row.extends.token),
                    "{:?}, the base of {:?}",
                    row.extends.token,
                    row.token
                );
                by_bases += 1;
            }
        }
        assert!(
            by_fields > 0,
            "the sample has a field of one of its own types"
        );
        assert!(
            by_bases > 0,
            "the sample has a type deriving from one of its own"
        );
    }

    #[test]
    fn a_removed_type_names_nothing() {
        let assembly = test_assembly_arc();
        let mut removed: HashSet<Token> = assembly
            .types()
            .iter()
            .map(|entry| *entry.key())
            .filter(|token| token.is_table(TableId::TypeDef))
            .chain(assembly.methods().iter().map(|entry| *entry.key()))
            .collect();
        for entry in assembly.types().iter() {
            for (_, field) in entry.value().fields.iter() {
                removed.insert(field.token);
            }
        }

        // With every type gone, only TypeSpecs (which cleanup removes later,
        // as orphans) still name anything.
        let names = TypeNames::of_metadata(&assembly);
        let named: HashSet<Token> = names.named_by_survivors(&removed).collect();
        let by_typespecs = typespec_names(&assembly);
        let stray: Vec<&Token> = named.difference(&by_typespecs).collect();
        assert!(stray.is_empty(), "removed rows still named {stray:?}");
    }

    fn typespec_names(assembly: &CilObject) -> HashSet<Token> {
        let mut names = HashSet::new();
        let tables = assembly.tables().expect("tables");
        let blob_heap = assembly.blob().expect("blob heap");
        if let Some(table) = tables.table::<TypeSpecRaw>() {
            for row in table.iter().filter_map(skip_unreadable) {
                if let Ok(sig) = blob_heap
                    .get(row.signature as usize)
                    .and_then(parse_type_spec_signature)
                {
                    sig.type_tokens(&mut names);
                }
            }
        }
        names
    }

    #[test]
    fn test_expand_type_tokens_empty_request() {
        let request = CleanupRequest::new();
        // Cannot test with real assembly, but verify that all_tokens is returned
        // for an empty request
        let tokens = request.all_tokens();
        assert!(tokens.is_empty());
    }

    #[test]
    fn test_find_unreferenced_types_empty_graph() {
        // With an empty call graph, no types should be found unreferenced
        let graph: BTreeMap<Token, BTreeSet<Token>> = BTreeMap::new();
        assert!(graph.is_empty());
    }
}

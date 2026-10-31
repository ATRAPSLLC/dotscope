//! Shared utilities for deobfuscation techniques.
//!
//! Provides common helpers used across multiple technique implementations:
//!
//! - **Type resolution**: [`resolve_constructor_type()`] and friends unify the pattern
//!   of walking CustomAttribute → constructor → declaring type across MethodDef and
//!   MemberRef indirections.
//! - **Name classification**: [`is_obfuscated_name()`] and [`is_special_name()`] identify
//!   obfuscated identifiers vs. protected .NET names.
//! - **Call-site counting**: [`build_call_site_counts()`] provides O(n) batch counting of
//!   call/callvirt targets.
//! - **Method name resolution**: [`is_method_named()`] checks if a token resolves to a
//!   method of a given name.
//! - **Blob parsing**: [`read_packed_len()`] decodes the .NET SerString packed length encoding.

use std::collections::{HashMap, HashSet};

use crate::{
    analysis::{SsaFunction, SsaOp, SsaVarId},
    metadata::{
        signatures::{parse_field_signature, TypeSignature},
        streams::Strings,
        tables::{
            skip_unreadable, ClassLayoutRaw, FieldRaw, MemberRefRaw, MetadataTable, MethodDefRaw,
            TableId, TypeDefRaw, TypeRefRaw,
        },
        token::Token,
        typesystem::{wellknown, PointerSize},
    },
    CilObject,
};

/// Determines a FieldRVA entry's data size from its type signature.
///
/// Handles two cases:
/// - **Primitive types** (e.g., `int64` for 8-byte arrays): size from `byte_size()`
/// - **Value types** with ClassLayout (e.g., `__StaticArrayInitTypeSize=40`):
///   size from the ClassLayout table's `class_size` column
pub(crate) fn get_field_data_size(assembly: &CilObject, field_rid: u32) -> Option<usize> {
    let tables = assembly.tables()?;
    let blobs = assembly.blob()?;

    let field_table = tables.table::<FieldRaw>()?;
    let field_row = field_table.get(field_rid).ok().flatten()?;

    let sig_data = blobs.get(field_row.signature as usize).ok()?;
    let field_sig = parse_field_signature(sig_data).ok()?;

    // Check primitive types first (int64, int32, etc.)
    // PointerSize only affects I/U (native int), which are not used in FieldRVA data.
    if let Some(size) = field_sig.base.byte_size(PointerSize::Bit32) {
        return Some(size);
    }

    match &field_sig.base {
        TypeSignature::ValueType(token) => {
            if token.table() != 0x02 {
                return None;
            }
            let type_rid = token.row();

            let class_layout_table = tables.table::<ClassLayoutRaw>()?;
            for layout in class_layout_table {
                let layout = match layout {
                    Ok(row) => row,
                    Err(e) => {
                        log::warn!("skipping unreadable metadata row: {e}");
                        continue;
                    }
                };
                if layout.parent == type_rid {
                    return Some(layout.class_size as usize);
                }
            }
            None
        }
        _ => None,
    }
}

/// Builds a mapping from SSA variable IDs to their defining operations.
///
/// Iterates over all blocks and instructions in the given SSA function,
/// collecting each instruction's destination variable (if any) into a
/// `HashMap`. This is a common first step in SSA-based analyses that need
/// to trace definitions back from variable uses.
///
/// # Arguments
///
/// * `ssa` - The SSA function to scan.
///
/// # Returns
///
/// A [`HashMap`] mapping each defined [`SsaVarId`] to its defining [`SsaOp`].
pub(crate) fn build_def_map(ssa: &SsaFunction) -> HashMap<SsaVarId, &SsaOp> {
    let mut defs = HashMap::new();
    for block in ssa.blocks() {
        for instr in block.instructions() {
            if let Some(dest) = instr.op().dest() {
                defs.insert(dest, instr.op());
            }
        }
    }
    defs
}

/// Removes the static field loads defining `values` that nothing reads any
/// more.
///
/// A pass that resolves what a static field holds rewrites the instructions
/// reading the loaded value, and the load itself is dead only once every
/// reader is gone. Whether it is comes from the function as it stands, not from
/// recorded use lists, which go stale as soon as an earlier pass rewrites an
/// instruction: a load another instruction still reads is kept.
///
/// # Arguments
///
/// * `ssa` - The SSA function to modify.
/// * `values` - Values whose `LoadStaticField` definitions may go.
///
/// # Returns
///
/// The number of loads removed.
pub fn remove_unread_static_loads(ssa: &mut SsaFunction, values: &HashSet<SsaVarId>) -> usize {
    let loads: Vec<(usize, usize)> = ssa
        .iter_instructions()
        .filter(|(_, _, instr)| {
            matches!(instr.op(), SsaOp::LoadStaticField { dest, .. } if values.contains(dest))
        })
        .map(|(block_idx, instr_idx, _)| (block_idx, instr_idx))
        .collect();
    ssa.remove_unread_instructions(loads).len()
}

/// Checks if a name contains obfuscation indicators (zero-width chars, PUA, spaces).
pub(crate) fn is_obfuscated_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }

    // ASCII spaces in identifiers are a strong obfuscation signal (BitMono FullRenamer).
    if name.contains(' ') {
        return true;
    }

    for c in name.chars() {
        match c {
            '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{E000}'..='\u{F8FF}' => return true,
            c if !c.is_ascii() && !c.is_alphabetic() => return true,
            _ => {}
        }
    }

    false
}

/// Checks if a name is a special .NET name that should not be renamed.
///
/// Protects constructors, module types, CLR-internal angle-bracket names,
/// and property/event accessor prefixes (get_, set_, add_, remove_).
pub(crate) fn is_special_name(name: &str) -> bool {
    if name == wellknown::members::CTOR || name == wellknown::members::CCTOR {
        return true;
    }

    if name == wellknown::members::MODULE_TYPE || name == wellknown::members::PRIVATE_IMPL {
        return true;
    }

    // Angle-bracket-wrapped names are CLR-internal (e.g. "<Generic Parameter>").
    if name.starts_with('<') && name.ends_with('>') {
        return true;
    }

    // Names containing spaces cannot be legitimate property/event accessors.
    if name.contains(' ') {
        return false;
    }

    if name.starts_with("get_")
        || name.starts_with("set_")
        || name.starts_with("add_")
        || name.starts_with("remove_")
    {
        return true;
    }

    false
}

/// Counts the number of `call` or `callvirt` instructions targeting each token
/// in `target_tokens`, scanning every method in `assembly` once.
///
/// The scan is O(n) in the total number of instructions across all methods,
/// regardless of how many target tokens are provided. Callers should collect
/// all candidate tokens first and pass them together rather than calling this
/// function once per token.
///
/// # Arguments
///
/// * `assembly` - The assembly to scan for call sites.
/// * `target_tokens` - Tokens to count call sites for. May be any iterator
///   of [`Token`] values (e.g., `Vec::iter().copied()`, `HashSet::iter().copied()`).
///
/// # Returns
///
/// A [`HashMap`] from each target token to its call-site count. Every token
/// in `target_tokens` is present in the map; tokens with no callers have a
/// count of `0`. Returns an empty map if `target_tokens` is empty.
///
/// # Examples
///
/// ```no_run
/// use crate::deobfuscation::utils::build_call_site_counts;
///
/// let candidates: Vec<Token> = collect_decryptor_candidates(&assembly);
/// let counts = build_call_site_counts(&assembly, candidates.iter().copied());
/// let active: Vec<Token> = candidates
///     .into_iter()
///     .filter(|t| *counts.get(t).unwrap_or(&0) >= 3)
///     .collect();
/// ```
pub(crate) fn build_call_site_counts(
    assembly: &CilObject,
    target_tokens: impl IntoIterator<Item = Token>,
) -> HashMap<Token, usize> {
    let targets: HashSet<Token> = target_tokens.into_iter().collect();
    if targets.is_empty() {
        return HashMap::new();
    }

    let mut counts: HashMap<Token, usize> = targets.iter().map(|&t| (t, 0)).collect();
    let mut memberref_cache: HashMap<Token, Option<Token>> = HashMap::new();

    for method_entry in assembly.methods() {
        let method = method_entry.value();
        for instr in method.instructions() {
            if instr.mnemonic == "call" || instr.mnemonic == "callvirt" {
                if let Some(token) = instr.get_token_operand() {
                    if let Some(count) = counts.get_mut(&token) {
                        *count = count.saturating_add(1);
                    } else if token.is_table(TableId::MemberRef) {
                        let resolved = memberref_cache
                            .entry(token)
                            .or_insert_with(|| assembly.resolver().resolve_memberref_method(token));
                        if let Some(resolved_token) = resolved {
                            if let Some(count) = counts.get_mut(resolved_token) {
                                *count = count.saturating_add(1);
                            }
                        }
                    }
                }
            }
        }
    }

    counts
}

/// Resolved type information from a constructor's declaring type.
///
/// Produced by [`resolve_constructor_type()`] when walking the CustomAttribute →
/// constructor → declaring type chain. Contains all metadata that different
/// technique implementations may need.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedType<'a> {
    /// Type name (e.g., `"ConfusedByAttribute"`).
    pub name: &'a str,
    /// Type namespace, if present (e.g., `"System.Runtime.CompilerServices"`).
    pub namespace: Option<&'a str>,
    /// TypeDef token for locally-defined types, `None` for external TypeRef types.
    pub typedef_token: Option<Token>,
    /// Whether the TypeRef has module scope (`resolution_scope` points to the Module table).
    pub has_module_scope: bool,
}

/// Resolves a constructor token to its declaring type information.
///
/// Dispatches on the constructor's table tag (MethodDef or MemberRef) to walk
/// the appropriate metadata tables and resolve the declaring type's name,
/// namespace, and token.
///
/// # Arguments
///
/// * `tag` - Table identifier of the constructor (typically `MethodDef` or `MemberRef`).
/// * `row` - Row index within the table.
/// * `methoddef_table` - Optional reference to the MethodDef table.
/// * `typedef_table` - Optional reference to the TypeDef table.
/// * `typeref_table` - Optional reference to the TypeRef table.
/// * `memberref_table` - Optional reference to the MemberRef table.
/// * `strings` - The `#Strings` heap for resolving name indices.
///
/// # Returns
///
/// [`Some(ResolvedType)`] with the declaring type's metadata, or `None` if
/// the constructor cannot be resolved (missing tables, invalid row, etc.).
pub(crate) fn resolve_constructor_type<'a>(
    tag: TableId,
    row: u32,
    methoddef_table: Option<&'a MetadataTable<'a, MethodDefRaw>>,
    typedef_table: Option<&'a MetadataTable<'a, TypeDefRaw>>,
    typeref_table: Option<&'a MetadataTable<'a, TypeRefRaw>>,
    memberref_table: Option<&'a MetadataTable<'a, MemberRefRaw>>,
    strings: &'a Strings<'a>,
) -> Option<ResolvedType<'a>> {
    match tag {
        TableId::MethodDef => {
            resolve_methoddef_declaring_type(row, methoddef_table, typedef_table, strings)
        }
        TableId::MemberRef => resolve_memberref_declaring_type(
            row,
            memberref_table,
            typedef_table,
            typeref_table,
            strings,
        ),
        _ => None,
    }
}

/// Resolves a MethodDef to its declaring TypeDef's name, namespace, and token.
///
/// Walks the TypeDef table to find the type that owns the given method RID
/// by checking `method_list` ranges.
pub(crate) fn resolve_methoddef_declaring_type<'a>(
    method_row: u32,
    methoddef_table: Option<&'a MetadataTable<'a, MethodDefRaw>>,
    typedef_table: Option<&'a MetadataTable<'a, TypeDefRaw>>,
    strings: &'a Strings<'a>,
) -> Option<ResolvedType<'a>> {
    let methoddef_table = methoddef_table?;
    let typedef_table = typedef_table?;
    let method = methoddef_table.get(method_row).ok().flatten()?;

    // No error channel here (the function answers `Option`), so an unreadable row is
    // reported and skipped rather than vanishing inside the iterator.
    let typedef = typedef_table
        .iter()
        .filter_map(skip_unreadable)
        .filter(|t| t.method_list <= method.rid)
        .last()?;

    let name = strings.get(typedef.type_name as usize).ok()?;
    let namespace = strings.get(typedef.type_namespace as usize).ok();

    Some(ResolvedType {
        name,
        namespace,
        typedef_token: Some(typedef.token),
        has_module_scope: false,
    })
}

/// Resolves a MemberRef to its declaring type's name, namespace, and token.
///
/// The MemberRef class column can point to TypeDef (local type) or TypeRef
/// (external reference). For TypeDef, the typedef token is included; for
/// TypeRef, the `has_module_scope` flag indicates whether the reference
/// resolves through the Module table.
pub(crate) fn resolve_memberref_declaring_type<'a>(
    memberref_row: u32,
    memberref_table: Option<&'a MetadataTable<'a, MemberRefRaw>>,
    typedef_table: Option<&'a MetadataTable<'a, TypeDefRaw>>,
    typeref_table: Option<&'a MetadataTable<'a, TypeRefRaw>>,
    strings: &'a Strings<'a>,
) -> Option<ResolvedType<'a>> {
    let memberref_table = memberref_table?;
    let memberref = memberref_table.get(memberref_row).ok().flatten()?;

    match memberref.class.tag {
        TableId::TypeDef => {
            let typedef_table = typedef_table?;
            let typedef = typedef_table.get(memberref.class.row).ok().flatten()?;
            let name = strings.get(typedef.type_name as usize).ok()?;
            let namespace = strings.get(typedef.type_namespace as usize).ok();
            Some(ResolvedType {
                name,
                namespace,
                typedef_token: Some(typedef.token),
                has_module_scope: false,
            })
        }
        TableId::TypeRef => {
            let typeref_table = typeref_table?;
            let typeref = typeref_table.get(memberref.class.row).ok().flatten()?;
            let name = strings.get(typeref.type_name as usize).ok()?;
            let namespace = strings.get(typeref.type_namespace as usize).ok();
            Some(ResolvedType {
                name,
                namespace,
                typedef_token: None,
                has_module_scope: typeref.resolution_scope.tag == TableId::Module,
            })
        }
        _ => None,
    }
}

/// Resolves a qualified method name for a call target token.
///
/// For MemberRef tokens (cross-assembly calls), uses [`CilTypeReference::fullname()`]
/// on the `declaredby` field to produce `"DeclaringType.MethodName"`
/// (e.g., `"System.Environment.FailFast"`). For MethodDef and MethodSpec tokens,
/// falls back to just the method name (the declaring type lookup for MethodDef
/// requires an O(n) scan via [`TokenResolver::declaring_type()`] which is too
/// expensive for batch scanning).
///
/// This enables patterns like `"Environment.FailFast"` to match only the BCL method,
/// not a user-defined method also named `FailFast`.
pub(crate) fn resolve_qualified_method_name(assembly: &CilObject, token: Token) -> Option<String> {
    // MemberRef: cheaply get declaring type from the declaredby field
    if token.table() == 0x0A {
        if let Some(member) = assembly.member_ref(&token) {
            if let Some(type_name) = member.declaredby.fullname() {
                return Some(format!("{}.{}", type_name, member.name));
            }
            return Some(member.name.clone());
        }
    }
    // MethodDef / MethodSpec: fall back to unqualified name
    assembly.resolve_method_name(token)
}

/// Scans all methods for calls matching any of the given name patterns.
///
/// For each method, checks every instruction with a token operand against the
/// list of `patterns`. If the resolved method name contains pattern `i`, the
/// method is recorded with that pattern index. Multiple patterns can match in
/// a single method.
///
/// Patterns are matched against **qualified** method names when available
/// (e.g., `"System.Environment.FailFast"` for MemberRef tokens). This allows
/// patterns to include the declaring type for precision (e.g., `"Environment.FailFast"`)
/// or remain method-name-only for backwards compatibility (e.g., `"get_UtcNow"`).
///
/// # Arguments
///
/// * `assembly` - The assembly to scan.
/// * `patterns` - Name substrings to match against resolved method names.
///
/// # Returns
///
/// A [`HashMap`] from method token to the set of matched pattern indices.
/// Only methods with at least one match are included.
pub(crate) fn find_methods_calling_apis(
    assembly: &CilObject,
    patterns: &[&str],
) -> HashMap<Token, Vec<usize>> {
    let mut results: HashMap<Token, Vec<usize>> = HashMap::new();

    for method_entry in assembly.methods() {
        let method = method_entry.value();
        let mut matched = Vec::new();

        for instr in method.instructions() {
            if let Some(token) = instr.get_token_operand() {
                if let Some(name) = resolve_qualified_method_name(assembly, token) {
                    for (i, pattern) in patterns.iter().enumerate() {
                        if name.contains(pattern) && !matched.contains(&i) {
                            matched.push(i);
                        }
                    }
                }
            }
        }

        if !matched.is_empty() {
            results.insert(method.token, matched);
        }
    }

    results
}

/// Filters candidate tokens by call-site count threshold.
///
/// Retains only candidates that are called at least `min_calls` times
/// according to the provided call-site counts. Returns a [`HashSet`] for
/// efficient membership testing in subsequent filtering stages.
///
/// # Arguments
///
/// * `candidates` - Tokens to filter (consumed).
/// * `counts` - Call-site counts (from [`build_call_site_counts`]).
/// * `min_calls` - Minimum number of call sites required to keep a token.
///
/// # Returns
///
/// A [`HashSet`] of tokens meeting the threshold.
pub(crate) fn filter_by_call_threshold(
    candidates: Vec<Token>,
    counts: &HashMap<Token, usize>,
    min_calls: usize,
) -> HashSet<Token> {
    candidates
        .into_iter()
        .filter(|t| *counts.get(t).unwrap_or(&0) >= min_calls)
        .collect()
}

/// Removes candidates whose method bodies call other candidates.
///
/// A real decryptor implements its own decryption logic — it does not delegate
/// to another decryptor. A method that calls another candidate is a **consumer**
/// (e.g., a SQLite error-string lookup that calls the actual string decryptor
/// for each entry), not a decryptor itself.
///
/// This filter eliminates a common class of false positives where legitimate
/// helper methods (lookup tables, error formatters) match the decryptor
/// signature and exceed the call-site threshold because they internally call
/// the real decryptor many times.
///
/// # Arguments
///
/// * `candidates` - Tokens that passed signature and threshold checks (consumed).
/// * `assembly` - The assembly for method body inspection.
///
/// # Returns
///
/// A [`HashSet`] containing only candidates whose bodies do not call any other
/// candidate. Methods whose bodies cannot be inspected are kept.
pub(crate) fn exclude_cross_calling_candidates(
    candidates: HashSet<Token>,
    assembly: &CilObject,
) -> HashSet<Token> {
    if candidates.len() <= 1 {
        return candidates;
    }

    candidates
        .iter()
        .filter(|token| {
            let Ok(method) = assembly.method(token) else {
                return true;
            };
            let calls_other = method.instructions().any(|instr| {
                instr
                    .get_token_operand()
                    .is_some_and(|t| t != **token && candidates.contains(&t))
            });
            if calls_other {
                log::trace!(
                    "exclude_cross_calling: dropping {} ({}) — calls another candidate",
                    token,
                    method.name
                );
            }
            !calls_other
        })
        .copied()
        .collect()
}

/// Builds a mapping from byte-array field tokens to their FieldRVA backing
/// field tokens by scanning `.cctor` methods for `RuntimeHelpers.InitializeArray`
/// patterns.
///
/// The .NET compiler emits this pattern to initialize static `byte[]` fields
/// from FieldRVA data:
/// ```text
/// ldtoken    <backing_field>        // FieldRVA-backed ExplicitLayout struct
/// call       RuntimeHelpers.InitializeArray(Array, RuntimeFieldHandle)
/// stsfld     <byte_array_field>     // byte[] field used in code
/// ```
///
/// # Returns
///
/// A [`HashMap`] mapping each byte-array field token to its backing field token.
pub(crate) fn build_init_array_map(assembly: &CilObject) -> HashMap<Token, Token> {
    let mut map = HashMap::new();

    for method_entry in assembly.methods() {
        let method = method_entry.value();

        if method.name != wellknown::members::CCTOR {
            continue;
        }

        let instructions: Vec<_> = method.instructions().collect();

        for (i, instr) in instructions.iter().enumerate() {
            if instr.mnemonic != "call" {
                continue;
            }
            let Some(call_token) = instr.get_token_operand() else {
                continue;
            };

            // Check if it's InitializeArray
            let is_init_array = assembly
                .refs_members()
                .get(&call_token)
                .is_some_and(|r| r.value().name == "InitializeArray");

            if !is_init_array {
                continue;
            }

            let Some(next_idx) = i.checked_add(1) else {
                continue;
            };
            if i < 1 || next_idx >= instructions.len() {
                continue;
            }

            // Find ldtoken before the call (within 3 instructions back)
            let mut backing_field_token = None;
            for j in (0..i).rev() {
                let Some(prev_instr) = instructions.get(j) else {
                    break;
                };
                if prev_instr.mnemonic == "ldtoken" {
                    backing_field_token = prev_instr.get_token_operand();
                    break;
                }
                if i.saturating_sub(j) > 3 {
                    break;
                }
            }

            // Find stsfld after the call
            let Some(stsfld_instr) = instructions.get(next_idx) else {
                continue;
            };
            if stsfld_instr.mnemonic != "stsfld" {
                continue;
            }

            if let (Some(backing), Some(byte_array)) =
                (backing_field_token, stsfld_instr.get_token_operand())
            {
                map.insert(byte_array, backing);
            }
        }
    }

    map
}

/// Checks if a name is a valid GUID string.
///
/// Expected pattern: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` (36 characters),
/// with dashes at positions 8, 13, 18, and 23 and hex digits everywhere else.
/// Both uppercase and lowercase hex digits are accepted.
pub(crate) fn is_guid_name(name: &str) -> bool {
    if name.len() != 36 {
        return false;
    }
    let bytes = name.as_bytes();
    let dash_positions = [8usize, 13, 18, 23];
    for &pos in &dash_positions {
        match bytes.get(pos) {
            Some(&b'-') => {}
            _ => return false,
        }
    }
    bytes.iter().enumerate().all(|(i, &b)| {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            true
        } else {
            b.is_ascii_hexdigit()
        }
    })
}

/// Resolves a CustomAttribute's constructor to its declaring type.
///
/// Convenience wrapper around [`resolve_constructor_type`] that extracts
/// the necessary tables and strings from the assembly, removing the need
/// for callers to pass 6+ arguments.
///
/// # Arguments
///
/// * `assembly` - The assembly containing the attribute.
/// * `attr` - The raw CustomAttribute row to resolve.
///
/// # Returns
///
/// [`Some(ResolvedType)`] with the declaring type's metadata, or `None` if
/// the constructor cannot be resolved.
pub(crate) fn resolve_custom_attr_type<'a>(
    assembly: &'a CilObject,
    attr: &crate::metadata::tables::CustomAttributeRaw,
) -> Option<ResolvedType<'a>> {
    let tables = assembly.tables()?;
    let strings = assembly.strings()?;

    resolve_constructor_type(
        attr.constructor.tag,
        attr.constructor.row,
        tables.table::<MethodDefRaw>(),
        tables.table::<TypeDefRaw>(),
        tables.table::<TypeRefRaw>(),
        tables.table::<MemberRefRaw>(),
        strings,
    )
}

/// Checks whether a metadata token resolves to a method named `name`.
///
/// The whole name: `ResolveMethod` is not `ResolveMethodHandle`, and
/// `get_Module` is not `get_ModuleHandle`.
///
/// # Arguments
///
/// * `assembly` - The assembly used to resolve the token.
/// * `token` - Metadata token to look up (MethodDef, MemberRef or MethodSpec).
/// * `name` - The method name.
///
/// # Returns
///
/// `true` if the token resolves to a method of that name, `false` if it does
/// not resolve or names another method.
pub(crate) fn is_method_named(assembly: &CilObject, token: Token, name: &str) -> bool {
    assembly
        .resolve_method_name(token)
        .is_some_and(|n| n == name)
}

#[cfg(test)]
mod tests {
    use crate::{
        analysis::{FieldRef, MethodRef, SsaFunctionBuilder, SsaOp, SsaType},
        deobfuscation::utils::{
            build_call_site_counts, is_method_named, is_obfuscated_name, is_special_name,
            remove_unread_static_loads, resolve_constructor_type,
        },
        metadata::{
            tables::{MemberRefRaw, MethodDefRaw, TableId, TypeDefRaw, TypeRefRaw},
            token::Token,
        },
        testkit::helpers::{load_sample, method_token, mono_mscorlib},
    };

    /// A static load goes once nothing reads it, and stays while an
    /// instruction the resolving pass did not rewrite still reads it.
    #[test]
    fn test_remove_unread_static_loads_keeps_loads_still_read() {
        let removed = |still_read: bool| {
            let field = FieldRef::new(Token::new(0x0400_0001));
            let mut loaded = None;
            let mut ssa = SsaFunctionBuilder::new(0, 0)
                .build_with(|f| {
                    let object = f.var();
                    loaded = Some(object);
                    f.block(0, |b| {
                        b.op_typed(
                            SsaOp::LoadStaticField {
                                dest: object,
                                field,
                            },
                            SsaType::Object,
                        );
                        // The field load the pass resolved, already a constant.
                        let _ = b.const_i32(1);
                        if still_read {
                            let _ = b.call(
                                MethodRef::new(Token::new(0x0A00_0001)),
                                &[object],
                                SsaType::I32,
                            );
                        }
                        b.ret();
                    });
                })
                .unwrap();
            let values = [loaded.unwrap()].into_iter().collect();
            let count = remove_unread_static_loads(&mut ssa, &values);
            let kept = matches!(
                ssa.block(0).unwrap().instructions()[0].op(),
                SsaOp::LoadStaticField { .. }
            );
            (count, kept)
        };
        assert_eq!(removed(false), (1, false), "an unread load is removed");
        assert_eq!(removed(true), (0, true), "a load still read is kept");
    }

    #[test]
    fn test_is_obfuscated_name_normal_names() {
        assert!(!is_obfuscated_name("Main"));
        assert!(!is_obfuscated_name("Program"));
        assert!(!is_obfuscated_name("get_Count"));
        assert!(!is_obfuscated_name(".ctor"));
        assert!(!is_obfuscated_name("<Module>"));
    }

    #[test]
    fn test_is_obfuscated_name_empty() {
        assert!(!is_obfuscated_name(""));
    }

    #[test]
    fn test_is_obfuscated_name_spaces() {
        assert!(is_obfuscated_name("Hello World"));
        assert!(is_obfuscated_name(" "));
    }

    #[test]
    fn test_is_obfuscated_name_zero_width() {
        assert!(is_obfuscated_name("\u{200B}"));
        assert!(is_obfuscated_name("a\u{FEFF}b"));
        assert!(is_obfuscated_name("\u{202A}test"));
    }

    #[test]
    fn test_is_obfuscated_name_pua() {
        assert!(is_obfuscated_name("\u{E000}"));
        assert!(is_obfuscated_name("abc\u{F800}"));
    }

    #[test]
    fn test_is_special_name_constructors() {
        assert!(is_special_name(".ctor"));
        assert!(is_special_name(".cctor"));
    }

    #[test]
    fn test_is_special_name_module_types() {
        assert!(is_special_name("<Module>"));
        assert!(is_special_name("<PrivateImplementationDetails>"));
    }

    #[test]
    fn test_is_special_name_clr_internal() {
        assert!(is_special_name("<Generic Parameter>"));
        // Closure names like <>c__DisplayClass0_0 are NOT wrapped in angle brackets
        // (they start with < but don't end with >), so they are not protected.
        assert!(!is_special_name("<>c__DisplayClass0_0"));
    }

    #[test]
    fn test_is_special_name_accessors() {
        assert!(is_special_name("get_Count"));
        assert!(is_special_name("set_Value"));
        assert!(is_special_name("add_Click"));
        assert!(is_special_name("remove_Changed"));
    }

    #[test]
    fn test_is_special_name_regular() {
        assert!(!is_special_name("Main"));
        assert!(!is_special_name("DoWork"));
        assert!(!is_special_name("ToString"));
    }

    #[test]
    fn test_is_special_name_spaces_not_special() {
        assert!(!is_special_name("get_ Count"));
        assert!(!is_special_name("Hello World"));
    }

    #[test]
    fn test_build_call_site_counts_empty_targets() {
        let asm = load_sample("packers/confuserex/1.6.0/original.exe");
        let counts = build_call_site_counts(&asm, std::iter::empty());
        assert!(counts.is_empty());
    }

    #[test]
    fn test_build_call_site_counts_nonexistent_token() {
        let asm = load_sample("packers/confuserex/1.6.0/original.exe");
        let bogus = Token::new(0x06FFFFFF);
        let counts = build_call_site_counts(&asm, std::iter::once(bogus));
        assert_eq!(counts.get(&bogus), Some(&0));
    }

    #[test]
    fn test_resolve_constructor_type_confuserex_marker() {
        let asm = load_sample("packers/confuserex/1.6.0/mkaring_normal.exe");

        let tables = asm.tables().expect("tables should be present");
        let strings = asm.strings().expect("strings should be present");

        let ca_table = tables
            .table::<crate::metadata::tables::CustomAttributeRaw>()
            .expect("CustomAttribute table should be present");

        let methoddef_table = tables.table::<MethodDefRaw>();
        let typedef_table = tables.table::<TypeDefRaw>();
        let typeref_table = tables.table::<TypeRefRaw>();
        let memberref_table = tables.table::<MemberRefRaw>();

        let mut found_marker = false;
        for attr in ca_table {
            let attr = match attr {
                Ok(row) => row,
                Err(e) => {
                    log::warn!("skipping unreadable metadata row: {e}");
                    continue;
                }
            };
            if let Some(resolved) = resolve_constructor_type(
                attr.constructor.tag,
                attr.constructor.row,
                methoddef_table,
                typedef_table,
                typeref_table,
                memberref_table,
                strings,
            ) {
                if resolved.name.contains("ConfuserVersion")
                    || resolved.name.contains("ConfusedByAttribute")
                {
                    found_marker = true;
                    // ConfuserEx defines marker attributes locally → has typedef_token
                    assert!(resolved.typedef_token.is_some());
                    break;
                }
            }
        }
        assert!(found_marker, "Expected to find ConfuserEx marker attribute");
    }

    #[test]
    fn test_resolve_constructor_type_unsupported_tag() {
        // Tag other than MethodDef/MemberRef should return None
        let asm = load_sample("packers/confuserex/1.6.0/original.exe");

        let tables = asm.tables().expect("tables should be present");
        let strings = asm.strings().expect("strings should be present");

        let result = resolve_constructor_type(
            TableId::Field,
            1,
            tables.table::<MethodDefRaw>(),
            tables.table::<TypeDefRaw>(),
            tables.table::<TypeRefRaw>(),
            tables.table::<MemberRefRaw>(),
            strings,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_is_method_named_with_real_assembly() {
        let asm = load_sample("packers/confuserex/1.6.0/original.exe");

        // Token for a nonexistent method should return false
        assert!(!is_method_named(&asm, Token::new(0x06FFFFFF), "Main"));
    }

    /// A method is named by its whole name, not by a prefix of it.
    #[test]
    fn a_method_is_named_by_its_whole_name() {
        let mscorlib = mono_mscorlib();
        let resolve = method_token(&mscorlib, "System.ModuleHandle", "ResolveMethodHandle", 1);
        assert!(is_method_named(&mscorlib, resolve, "ResolveMethodHandle"));
        assert!(!is_method_named(&mscorlib, resolve, "ResolveMethod"));
    }
}

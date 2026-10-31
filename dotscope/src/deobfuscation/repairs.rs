//! Repairs of the ECMA-335 violations obfuscators plant in metadata.
//!
//! Each repair is a [`MetadataRepair`]: it detects its violation in the raw tables, and
//! applies its repair to the [`CilAssembly`] that cleanup regenerates. [`REPAIRS`] lists
//! them all, so "does this assembly need repair" ([`needs_repair`]) and "repair it"
//! ([`apply_repairs`]) ask the same repairs the same question.

use std::collections::{HashMap, HashSet};

use crate::{
    cilassembly::{execute_cleanup, CilAssembly, CleanupRequest},
    compiler::EventKind,
    deobfuscation::context::AnalysisContext,
    metadata::{
        streams::{Guid, Strings, TablesHeader},
        tables::{
            skip_unreadable, DeclSecurityRaw, FieldRaw, MethodDefRaw, ModuleRaw, NestedClassRaw,
            TableDataOwned, TableId, TypeDefRaw,
        },
        token::Token,
        validation::ValidationConfig,
    },
    CilAssemblyView, CilObject,
};

/// The raw metadata a repair reads: the tables and the heaps they index.
pub struct RawMetadata<'a> {
    tables: &'a TablesHeader<'a>,
    strings: Option<&'a Strings<'a>>,
    guids: Option<&'a Guid<'a>>,
    /// Whether the tables stream is the compressed `#~`, outside which ENC tables mean
    /// something.
    compressed: bool,
}

impl<'a> RawMetadata<'a> {
    /// The raw metadata of a loaded assembly, if it has tables.
    pub fn of_object(assembly: &'a CilObject) -> Option<Self> {
        Some(RawMetadata {
            tables: assembly.tables()?,
            strings: assembly.strings(),
            guids: assembly.guids(),
            compressed: assembly
                .metadata_root()
                .tables_stream()
                .is_some_and(|s| s.name == "#~"),
        })
    }

    /// The raw metadata of an assembly being edited, if it has tables.
    pub fn of_assembly(assembly: &'a CilAssembly) -> Option<Self> {
        let view = assembly.view();
        Some(RawMetadata {
            tables: view.tables()?,
            strings: view.strings(),
            guids: view.guids(),
            compressed: view
                .metadata_root()
                .tables_stream()
                .is_some_and(|s| s.name == "#~"),
        })
    }

    /// The size of the `#Strings` heap in bytes.
    fn strings_size(&self) -> usize {
        self.strings.map_or(0, |s| s.data().len())
    }

    /// The number of entries in the `#GUID` heap.
    fn guid_count(&self) -> u32 {
        self.guids.map_or(0, |g| {
            u32::try_from(g.data().len() / 16).unwrap_or(u32::MAX)
        })
    }
}

/// An ECMA-335 violation obfuscators plant in metadata, and its repair.
pub trait MetadataRepair: Sync {
    /// Whether `metadata` holds the violation.
    fn detect(&self, metadata: &RawMetadata) -> bool;

    /// Proposes to `request` rows whose removal repairs the violation. Cleanup withdraws those
    /// surviving code still names before anything is removed, and [`MetadataRepair::apply`]
    /// repairs what it withdrew.
    fn propose(&self, _metadata: &RawMetadata, _request: &mut CleanupRequest) {}

    /// Repairs the violation in `assembly`, adding to `request` what the cleanup executor
    /// removes rather than the repair itself.
    fn apply(
        &self,
        assembly: &mut CilAssembly,
        request: &mut CleanupRequest,
        ctx: &AnalysisContext,
    );
}

/// Every repair, in the order they are applied.
pub const REPAIRS: &[&dyn MetadataRepair] = &[
    // ECMA-335 §22.30 rule 1: the Module table holds exactly one row; .NET Reactor's
    // SuppressIldasm and ConfuserEx's invalid metadata add a second.
    &SingletonTable {
        table: TableId::Module,
        rule: "ECMA-335 §22.30 rule 1",
    },
    // ECMA-335 §22.2 rule 1: the Assembly table holds at most one row; .NET Reactor's
    // SuppressIldasm and ConfuserEx's invalid metadata add a second.
    &SingletonTable {
        table: TableId::Assembly,
        rule: "ECMA-335 §22.2 rule 1",
    },
    &ModuleEncIds,
    &InertDeclSecurity,
    &EncTablesOutsideDelta,
    &DuplicateTypeDefs,
    &GlobalMemberAccess,
];

/// Whether any repair detects its violation in `assembly`.
pub fn needs_repair(assembly: &CilObject) -> bool {
    RawMetadata::of_object(assembly)
        .is_some_and(|metadata| REPAIRS.iter().any(|repair| repair.detect(&metadata)))
}

/// Proposes to `request` the removals of every repair whose violation `assembly` holds.
pub fn propose_removals(assembly: &CilObject, request: &mut CleanupRequest) {
    if let Some(metadata) = RawMetadata::of_object(assembly) {
        for repair in REPAIRS {
            if repair.detect(&metadata) {
                repair.propose(&metadata, request);
            }
        }
    }
}

/// Applies every repair whose violation `assembly` holds.
pub fn apply_repairs(
    assembly: &mut CilAssembly,
    request: &mut CleanupRequest,
    ctx: &AnalysisContext,
) {
    for repair in REPAIRS {
        let detected =
            RawMetadata::of_assembly(assembly).is_some_and(|metadata| repair.detect(&metadata));
        if detected {
            repair.apply(assembly, request, ctx);
        }
    }
}

/// Records a repair as an event and in the log.
fn report(ctx: &AnalysisContext, message: String) {
    log::info!("{message}");
    ctx.events
        .record(EventKind::ArtifactRemoved)
        .message(message);
}

/// A table ECMA-335 limits to one row, holding more: the rows after the first are removed,
/// keeping the original identity.
struct SingletonTable {
    table: TableId,
    rule: &'static str,
}

impl MetadataRepair for SingletonTable {
    fn detect(&self, metadata: &RawMetadata) -> bool {
        metadata.tables.table_row_count(self.table) > 1
    }

    fn apply(&self, assembly: &mut CilAssembly, _: &mut CleanupRequest, ctx: &AnalysisContext) {
        let rows = assembly.original_table_row_count(self.table);
        for rid in (2..=rows).rev() {
            if let Err(e) = assembly.table_row_remove(self.table, rid) {
                log::warn!("Failed to remove {:?} row {rid}: {e}", self.table);
            }
        }
        report(
            ctx,
            format!(
                "Repaired {:?} table: removed {} row(s) after the first ({} violation)",
                self.table,
                rows.saturating_sub(1),
                self.rule
            ),
        );
    }
}

/// ENCLog and ENCMap rows in compressed (`#~`) metadata: the tables describe an
/// edit-and-continue delta, which compressed metadata is not, so the runtime has no use for
/// them; ConfuserEx's invalid metadata adds them. They are removed.
struct EncTablesOutsideDelta;

impl MetadataRepair for EncTablesOutsideDelta {
    fn detect(&self, metadata: &RawMetadata) -> bool {
        metadata.compressed
            && (metadata.tables.table_row_count(TableId::EncLog) > 0
                || metadata.tables.table_row_count(TableId::EncMap) > 0)
    }

    fn apply(&self, assembly: &mut CilAssembly, _: &mut CleanupRequest, ctx: &AnalysisContext) {
        let mut removed = 0u32;
        for table in [TableId::EncLog, TableId::EncMap] {
            let rows = assembly.original_table_row_count(table);
            for rid in (1..=rows).rev() {
                match assembly.table_row_remove(table, rid) {
                    Ok(()) => removed = removed.saturating_add(1),
                    Err(e) => log::warn!("Failed to remove {table:?} row {rid}: {e}"),
                }
            }
        }
        report(
            ctx,
            format!("Removed {removed} ENC table row(s) from compressed metadata"),
        );
    }
}

/// Module row 1's `EncId` / `EncBaseId` outside the `#GUID` heap (ECMA-335 §22.30: 0 or an
/// entry of the heap; .NET Reactor's SuppressIldasm sets 0xFFFF): they become 0, the "no
/// value" index.
struct ModuleEncIds;

impl ModuleEncIds {
    /// Module row 1 with its out-of-heap ENC indices cleared, if it has any.
    fn repaired_row(metadata: &RawMetadata) -> Option<ModuleRaw> {
        let row = metadata
            .tables
            .table::<ModuleRaw>()?
            .get(1)
            .ok()
            .flatten()?;
        let guids = metadata.guid_count();
        let bad_encid = row.encid > guids;
        let bad_encbaseid = row.encbaseid > guids;
        (bad_encid || bad_encbaseid).then_some(ModuleRaw {
            encid: if bad_encid { 0 } else { row.encid },
            encbaseid: if bad_encbaseid { 0 } else { row.encbaseid },
            ..row
        })
    }
}

impl MetadataRepair for ModuleEncIds {
    fn detect(&self, metadata: &RawMetadata) -> bool {
        Self::repaired_row(metadata).is_some()
    }

    fn apply(&self, assembly: &mut CilAssembly, _: &mut CleanupRequest, ctx: &AnalysisContext) {
        let Some(fixed) = RawMetadata::of_assembly(assembly).and_then(|m| Self::repaired_row(&m))
        else {
            return;
        };
        if let Err(e) = assembly.table_row_update(TableId::Module, 1, TableDataOwned::Module(fixed))
        {
            log::warn!("Failed to repair Module row 1's ENC indices: {e}");
            return;
        }
        report(
            ctx,
            "Repaired Module row 1: cleared ENC indices outside the #GUID heap".to_string(),
        );
    }
}

/// DeclSecurity rows whose parent is the null reference: they protect nothing, so removing
/// them changes nothing the runtime does. A parent whose coded-index tag names no table
/// reads as null too (ConfuserEx's invalid metadata adds such a row).
struct InertDeclSecurity;

impl InertDeclSecurity {
    /// The rows of DeclSecurity rows with a null parent, highest first.
    fn inert_rows(metadata: &RawMetadata) -> Vec<u32> {
        let Some(table) = metadata.tables.table::<DeclSecurityRaw>() else {
            return Vec::new();
        };
        let mut rows: Vec<u32> = table
            .into_iter()
            .filter_map(skip_unreadable)
            .filter(|row| row.parent.row == 0)
            .map(|row| row.rid)
            .collect();
        rows.sort_unstable_by(|a, b| b.cmp(a));
        rows
    }
}

impl MetadataRepair for InertDeclSecurity {
    fn detect(&self, metadata: &RawMetadata) -> bool {
        !Self::inert_rows(metadata).is_empty()
    }

    fn apply(&self, assembly: &mut CilAssembly, _: &mut CleanupRequest, ctx: &AnalysisContext) {
        let rows = RawMetadata::of_assembly(assembly)
            .map(|m| Self::inert_rows(&m))
            .unwrap_or_default();
        for &rid in &rows {
            if let Err(e) = assembly.table_row_remove(TableId::DeclSecurity, rid) {
                log::warn!("Failed to remove DeclSecurity row {rid}: {e}");
            }
        }
        report(
            ctx,
            format!(
                "Removed {} DeclSecurity row(s) whose parent is the null reference",
                rows.len()
            ),
        );
    }
}

/// TypeDef rows repeating another's (name, namespace, enclosing class) (ECMA-335 §22.37
/// rules 29 and 30): BitMono injects duplicate nested types such as `<>c`, and ConfuserEx's
/// invalid metadata duplicate top-level ones. Every duplicate is proposed to cleanup for removal,
/// which keeps those surviving code still names; a kept duplicate gets a name of its own, the
/// same row to everything that names it.
struct DuplicateTypeDefs;

/// What ECMA-335 §22.37 rules 29 and 30 key a TypeDef by: its name, its namespace and its
/// enclosing TypeDef row (0 for a top-level type).
type TypeKey = (String, String, u32);

/// A TypeDef row repeating an earlier row's key.
struct Duplicate {
    row: TypeDefRaw,
    key: TypeKey,
}

impl DuplicateTypeDefs {
    /// The key of every TypeDef row outside `gone`, and the rows repeating an earlier row's
    /// key. A row cleanup deletes collides with nothing, so of the rows sharing a key the
    /// first that stays keeps its name.
    fn find(metadata: &RawMetadata, gone: &HashSet<Token>) -> (HashSet<TypeKey>, Vec<Duplicate>) {
        let Some(strings) = metadata.strings else {
            return (HashSet::new(), Vec::new());
        };
        let enclosing_of: HashMap<u32, u32> = metadata
            .tables
            .table::<NestedClassRaw>()
            .map(|rows| {
                rows.into_iter()
                    .filter_map(skip_unreadable)
                    .map(|r| (r.nested_class, r.enclosing_class))
                    .collect()
            })
            .unwrap_or_default();

        let mut groups: Vec<(TypeKey, Vec<TypeDefRaw>)> = Vec::new();
        let mut group_of: HashMap<TypeKey, usize> = HashMap::new();
        for row in metadata
            .tables
            .table::<TypeDefRaw>()
            .into_iter()
            .flatten()
            .filter_map(skip_unreadable)
            .filter(|row| !gone.contains(&row.token))
        {
            let key = (
                strings
                    .get(row.type_name as usize)
                    .unwrap_or_default()
                    .to_string(),
                strings
                    .get(row.type_namespace as usize)
                    .unwrap_or_default()
                    .to_string(),
                enclosing_of.get(&row.rid).copied().unwrap_or(0),
            );
            match group_of.get(&key).and_then(|&index| groups.get_mut(index)) {
                Some((_, rows)) => rows.push(row),
                None => {
                    group_of.insert(key.clone(), groups.len());
                    groups.push((key, vec![row]));
                }
            }
        }

        let duplicates = groups
            .iter()
            .flat_map(|(key, rows)| {
                rows.iter().skip(1).map(|row| Duplicate {
                    row: row.clone(),
                    key: key.clone(),
                })
            })
            .collect();
        (group_of.into_keys().collect(), duplicates)
    }

    /// The TypeDef rows cleanup deletes: `request` executed on a copy of `assembly`, so the
    /// rows it empties and removes count as well as those it names. Failing that, the rows
    /// `request` names.
    fn gone(assembly: &CilAssembly, request: &CleanupRequest) -> HashSet<Token> {
        let named = || request.types().copied().collect();
        let view = match CilAssemblyView::from_mem_with_validation(
            assembly.view().data().to_vec(),
            ValidationConfig::disabled(),
        ) {
            Ok(view) => view,
            Err(e) => {
                log::warn!("Failed to copy the assembly to run its cleanup on: {e}");
                return named();
            }
        };
        let mut copy = CilAssembly::new(view);
        if let Err(e) = execute_cleanup(&mut copy, request) {
            log::warn!("Failed to run the cleanup on a copy of the assembly: {e}");
            return named();
        }
        (1..=copy.original_table_row_count(TableId::TypeDef))
            .filter(|&rid| copy.changes().is_row_deleted(TableId::TypeDef, rid))
            .map(|rid| Token::from_parts(TableId::TypeDef, rid))
            .collect()
    }
}

impl MetadataRepair for DuplicateTypeDefs {
    fn detect(&self, metadata: &RawMetadata) -> bool {
        !Self::find(metadata, &HashSet::new()).1.is_empty()
    }

    fn propose(&self, metadata: &RawMetadata, request: &mut CleanupRequest) {
        request.add_types(
            Self::find(metadata, &HashSet::new())
                .1
                .iter()
                .map(|d| d.row.token),
        );
    }

    fn apply(
        &self,
        assembly: &mut CilAssembly,
        request: &mut CleanupRequest,
        ctx: &AnalysisContext,
    ) {
        // Among the rows that survive cleanup: the code generator's
        // `<PrivateImplementationDetails>` keeps its name once cleanup removes the one the
        // obfuscator emptied
        let gone = Self::gone(assembly, request);
        let Some((mut keys, duplicates)) =
            RawMetadata::of_assembly(assembly).map(|m| Self::find(&m, &gone))
        else {
            return;
        };

        let mut renamed = 0usize;
        for Duplicate { mut row, key } in duplicates {
            let (name, namespace, enclosing) = key;
            let mut unique = format!("{name}_{}", row.rid);
            while !keys.insert((unique.clone(), namespace.clone(), enclosing)) {
                unique.push('_');
            }
            let rid = row.rid;
            let renaming = assembly.string_get_or_add(&unique).and_then(|name| {
                row.type_name = name.placeholder();
                assembly.table_row_update(TableId::TypeDef, rid, TableDataOwned::TypeDef(row))
            });
            match renaming {
                Ok(_) => renamed = renamed.saturating_add(1),
                Err(e) => log::warn!("Failed to rename duplicate TypeDef row {rid}: {e}"),
            }
        }
        if renamed > 0 {
            report(
                ctx,
                format!(
                    "Renamed {renamed} duplicate TypeDef(s) that surviving code still names (ECMA-335 §22.37 rules 29, 30)"
                ),
            );
        }
    }
}

/// `<Module>` fields and methods with an accessibility a global member may not have:
/// ECMA-335 §22.15 rule 16 and §22.26 rule 19 allow only CompilerControlled, Private and
/// Public, and obfuscators (ConfuserEx, .NET Reactor, BitMono) give their injected global
/// members Assembly. The CLR runs them, so the repair must not change what can access them:
/// such a member becomes Public, which every caller Assembly admits can still reach. Private
/// would not do: the runtime enforces it on global members (measured: ConfuserEx's constants
/// sample, its global members made Private, throws `MethodAccessException` on the .NET
/// Framework and fails on Mono; made Public, it prints the original's output).
struct GlobalMemberAccess;

/// The `<Module>` members whose accessibility a repair makes Public.
#[derive(Default)]
struct GlobalMembers {
    fields: Vec<FieldRaw>,
    methods: Vec<MethodDefRaw>,
}

impl GlobalMemberAccess {
    /// MemberAccessMask, ECMA-335 §II.23.1.5 and §II.23.1.10.
    const ACCESS_MASK: u32 = 0x0007;
    /// The accessibilities a global member may have: CompilerControlled, Private, Public.
    const ALLOWED: [u32; 3] = [0x0000, 0x0001, 0x0006];
    const PUBLIC: u32 = 0x0006;

    /// The `<Module>` members with an accessibility not allowed, each made Public.
    fn repaired_members(metadata: &RawMetadata) -> GlobalMembers {
        let Some(typedefs) = metadata.tables.table::<TypeDefRaw>() else {
            return GlobalMembers::default();
        };
        // Fetched by row, not by position among the readable rows: in a damaged assembly
        // an unreadable row would otherwise shift `<Module>` (row 1) onto another type.
        let Some(module_type) = typedefs.get(1).ok().flatten() else {
            return GlobalMembers::default();
        };
        let (field_end, method_end) = match typedefs.get(2) {
            Ok(Some(next)) => (next.field_list, next.method_list),
            _ => (
                metadata
                    .tables
                    .table_row_count(TableId::Field)
                    .saturating_add(1),
                metadata
                    .tables
                    .table_row_count(TableId::MethodDef)
                    .saturating_add(1),
            ),
        };
        let repaired = |flags: u32| {
            (!Self::ALLOWED.contains(&(flags & Self::ACCESS_MASK)))
                .then_some((flags & !Self::ACCESS_MASK) | Self::PUBLIC)
        };
        let fields = metadata
            .tables
            .table::<FieldRaw>()
            .map_or_else(Vec::new, |fields| {
                (module_type.field_list..field_end)
                    .filter_map(|rid| {
                        let field = fields.get(rid).ok().flatten()?;
                        let flags = repaired(field.flags)?;
                        Some(FieldRaw { flags, ..field })
                    })
                    .collect()
            });
        let methods = metadata
            .tables
            .table::<MethodDefRaw>()
            .map_or_else(Vec::new, |methods| {
                (module_type.method_list..method_end)
                    .filter_map(|rid| {
                        let method = methods.get(rid).ok().flatten()?;
                        let flags = repaired(method.flags)?;
                        Some(MethodDefRaw { flags, ..method })
                    })
                    .collect()
            });
        GlobalMembers { fields, methods }
    }
}

impl MetadataRepair for GlobalMemberAccess {
    fn detect(&self, metadata: &RawMetadata) -> bool {
        let members = Self::repaired_members(metadata);
        !members.fields.is_empty() || !members.methods.is_empty()
    }

    fn apply(&self, assembly: &mut CilAssembly, _: &mut CleanupRequest, ctx: &AnalysisContext) {
        let members = RawMetadata::of_assembly(assembly)
            .map(|m| Self::repaired_members(&m))
            .unwrap_or_default();
        let mut repaired = 0usize;
        for field in members.fields {
            let rid = field.rid;
            match assembly.table_row_update(TableId::Field, rid, TableDataOwned::Field(field)) {
                Ok(_) => repaired = repaired.saturating_add(1),
                Err(e) => log::warn!("Failed to make <Module> field {rid} public: {e}"),
            }
        }
        for method in members.methods {
            let rid = method.rid;
            match assembly.table_row_update(
                TableId::MethodDef,
                rid,
                TableDataOwned::MethodDef(method),
            ) {
                Ok(_) => repaired = repaired.saturating_add(1),
                Err(e) => log::warn!("Failed to make <Module> method {rid} public: {e}"),
            }
        }
        report(
            ctx,
            format!(
                "Made {repaired} <Module> member(s) public: their accessibility is not allowed for a global member (ECMA-335 §22.15, §22.26)"
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        analysis::CallGraph,
        cilassembly::ClassBuilder,
        metadata::{signatures::TypeSignature, tables::TypeDefBuilder},
        testkit::helpers::load_sample,
        Error,
    };

    /// ConfuserEx's invalid metadata, without anti-tamper (whose encrypted bodies the
    /// writer cannot re-encode before the deobfuscator decrypts them).
    const INVALID_METADATA: &str = "packers/confuserex/1.6.0/mkaring_invalidmetadata.exe";

    /// The number of rows of `table` in `assembly`.
    fn rows(assembly: &CilObject, table: TableId) -> u32 {
        assembly.tables().map_or(0, |t| t.table_row_count(table))
    }

    #[test]
    fn a_clean_assembly_needs_no_repair() {
        for sample in [
            "packers/confuserex/1.6.0/original.exe",
            "packers/bitmono/0.45.0/original.exe",
        ] {
            let metadata_owner = load_sample(sample);
            let metadata = RawMetadata::of_object(&metadata_owner).expect("tables");
            for (i, repair) in REPAIRS.iter().enumerate() {
                assert!(!repair.detect(&metadata), "{sample}: repair {i} detects");
            }
        }
    }

    #[test]
    fn confuserex_invalid_metadata_is_repaired_to_valid_metadata() {
        let sample = INVALID_METADATA;
        let original = load_sample(sample);
        assert!(needs_repair(&original), "{sample}");
        assert_eq!(rows(&original, TableId::Module), 2, "{sample}");
        assert_eq!(rows(&original, TableId::Assembly), 2, "{sample}");

        let mut assembly = load_sample(sample).into_assembly();
        let ctx = AnalysisContext::new(Arc::new(CallGraph::new()));
        let mut request = CleanupRequest::new();
        apply_repairs(&mut assembly, &mut request, &ctx);
        let bytes = assembly.to_memory().expect("write");

        let repaired = CilObject::from_mem_with_validation(bytes, ValidationConfig::strict())
            .unwrap_or_else(|e| panic!("{sample}: repaired output fails validation: {e}"));
        assert!(!needs_repair(&repaired), "{sample}");
        assert_eq!(rows(&repaired, TableId::Module), 1, "{sample}");
        assert_eq!(rows(&repaired, TableId::Assembly), 1, "{sample}");
        assert_eq!(rows(&repaired, TableId::EncLog), 0, "{sample}");
        assert_eq!(rows(&repaired, TableId::EncMap), 0, "{sample}");
        assert_eq!(
            rows(&repaired, TableId::DeclSecurity),
            rows(&original, TableId::DeclSecurity) - 1,
            "{sample}"
        );
        assert_eq!(
            repaired.module().map(|m| m.name.clone()),
            original.module().map(|m| m.name.clone()),
            "{sample}"
        );
    }

    #[test]
    fn netreactor_suppress_ildasm_is_repaired() {
        let sample = "packers/netreactor/7.5.0/reactor_suppressildasm.exe";
        let original = load_sample(sample);
        let module = |assembly: &CilObject| {
            let tables = assembly.tables().expect("tables");
            tables
                .table::<ModuleRaw>()
                .expect("Module")
                .get(1)
                .unwrap()
                .unwrap()
        };
        let guids = |assembly: &CilObject| {
            u32::try_from(assembly.guids().map_or(0, |g| g.data().len() / 16)).unwrap()
        };
        assert_eq!(rows(&original, TableId::Module), 2);
        assert_eq!(rows(&original, TableId::Assembly), 2);
        // SuppressIldasm sets EncBaseId to 0xFFFF.
        assert!(module(&original).encbaseid > guids(&original));

        let mut assembly = original.into_assembly();
        let ctx = AnalysisContext::new(Arc::new(CallGraph::new()));
        apply_repairs(&mut assembly, &mut CleanupRequest::new(), &ctx);
        let repaired = CilObject::from_mem_with_validation(
            assembly.to_memory().expect("write"),
            ValidationConfig::analysis(),
        )
        .expect("reload");

        assert_eq!(rows(&repaired, TableId::Module), 1);
        assert_eq!(rows(&repaired, TableId::Assembly), 1);
        let row = module(&repaired);
        assert!(row.encid <= guids(&repaired) && row.encbaseid <= guids(&repaired));
        assert!(!needs_repair(&repaired));
    }

    /// The flags of every `<Module>` field and method, by table and row.
    fn global_member_flags(assembly: &CilObject) -> Vec<(TableId, u32, u32)> {
        let tables = assembly.tables().expect("tables");
        let typedefs = tables.table::<TypeDefRaw>().expect("TypeDef");
        let module_type = typedefs.get(1).expect("row").expect("<Module>");
        let next = typedefs.get(2).expect("row").expect("a second type");
        let fields = tables.table::<FieldRaw>().expect("Field");
        let methods = tables.table::<MethodDefRaw>().expect("MethodDef");
        (module_type.field_list..next.field_list)
            .map(|rid| (TableId::Field, rid, fields.get(rid).unwrap().unwrap().flags))
            .chain((module_type.method_list..next.method_list).map(|rid| {
                (
                    TableId::MethodDef,
                    rid,
                    methods.get(rid).unwrap().unwrap().flags,
                )
            }))
            .collect()
    }

    #[test]
    fn global_members_with_assembly_access_become_public() {
        let sample = "packers/confuserex/1.6.0/mkaring_constants.exe";
        let original = load_sample(sample);
        let before = global_member_flags(&original);
        // ConfuserEx's constants protection injects Assembly (3) global members.
        assert!(before.iter().any(|&(_, _, flags)| flags & 0x7 == 0x3));

        let mut assembly = original.into_assembly();
        let ctx = AnalysisContext::new(Arc::new(CallGraph::new()));
        apply_repairs(&mut assembly, &mut CleanupRequest::new(), &ctx);
        let repaired = CilObject::from_mem_with_validation(
            assembly.to_memory().expect("write"),
            ValidationConfig::analysis(),
        )
        .expect("reload");

        let after = global_member_flags(&repaired);
        assert_eq!(after.len(), before.len());
        for (&(table, rid, old), &(_, _, new)) in before.iter().zip(&after) {
            let expected = if matches!(old & 0x7, 0x0 | 0x1 | 0x6) {
                old
            } else {
                (old & !0x7) | 0x6
            };
            assert_eq!(new, expected, "{table:?} row {rid}: {old:#06x}");
        }
        assert!(!needs_repair(&repaired));
    }

    /// The duplicate TypeDef tokens of `assembly`.
    fn duplicates(assembly: &CilObject) -> Vec<Token> {
        RawMetadata::of_object(assembly)
            .map(|m| {
                DuplicateTypeDefs::find(&m, &HashSet::new())
                    .1
                    .iter()
                    .map(|d| d.row.token)
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn a_duplicate_surviving_code_names_is_renamed_not_removed() {
        // BitMono 0.45 nests 91 key holders all named `<>c` under one type; the entry point
        // reads their fields.
        let sample = "packers/bitmono/0.45.0/bitmono_maximum.exe";
        let original = load_sample(sample);
        let named = duplicates(&original);
        assert_eq!(named.len(), 90);
        let types = original
            .tables()
            .map_or(0, |t| t.table_row_count(TableId::TypeDef));

        let mut request = CleanupRequest::new();
        propose_removals(&original, &mut request);
        assert_eq!(
            request.types().count(),
            named.len(),
            "every duplicate is proposed"
        );
        // What cleanup's retraction does for every row surviving code still names.
        for &token in &named {
            request.withdraw(token);
        }

        let mut assembly = original.into_assembly();
        let ctx = AnalysisContext::new(Arc::new(CallGraph::new()));
        apply_repairs(&mut assembly, &mut request, &ctx);
        assembly.add_cleanup(&request);
        let repaired = CilObject::from_mem_with_validation(
            assembly
                .to_memory()
                .expect("a renamed duplicate leaves nothing dangling"),
            ValidationConfig::analysis(),
        )
        .expect("reload");

        assert!(duplicates(&repaired).is_empty());
        assert_eq!(
            rows(&repaired, TableId::TypeDef),
            types,
            "no type is removed"
        );
    }

    /// A duplicate whose twin cleanup removes collides with nothing and keeps its name: the
    /// code generator's `<PrivateImplementationDetails>` came out `_26` once the obfuscator's
    /// was gone.
    #[test]
    fn a_duplicate_whose_twin_is_removed_keeps_its_name() {
        // Two types of one name, written out as the code generator's lands before cleanup
        let mut assembly = load_sample("packers/confuserex/1.6.0/original.exe").into_assembly();
        for _ in 0..2 {
            TypeDefBuilder::new()
                .name("Twin")
                .namespace("Repairs")
                .build(&mut assembly)
                .unwrap();
        }
        let twins = CilObject::from_mem_with_validation(
            assembly.to_memory().unwrap(),
            ValidationConfig::analysis(),
        )
        .unwrap();
        let mut tokens: Vec<Token> = twins
            .types()
            .iter()
            .filter(|entry| entry.value().namespace == "Repairs")
            .map(|entry| *entry.key())
            .collect();
        tokens.sort();
        assert_eq!(tokens.len(), 2);

        // Empty types kept: the twins have no members, and only the duplicate is in question
        let mut request = CleanupRequest::with_settings(true, false);
        request.add_type(tokens[0]);
        let mut assembly = twins.into_assembly();
        let ctx = AnalysisContext::new(Arc::new(CallGraph::new()));
        apply_repairs(&mut assembly, &mut request, &ctx);
        assembly.add_cleanup(&request);
        let repaired = CilObject::from_mem_with_validation(
            assembly.to_memory().unwrap(),
            ValidationConfig::analysis(),
        )
        .unwrap();

        let names: Vec<String> = repaired
            .types()
            .iter()
            .filter(|entry| entry.value().namespace == "Repairs")
            .map(|entry| entry.value().name.clone())
            .collect();
        assert_eq!(names, ["Twin"]);
    }

    #[test]
    fn the_name_goes_to_the_duplicate_cleanup_keeps() {
        // Three types of one name: one cleanup empties of its field, one without members (as
        // ConfuserEx leaves the compiler's `<PrivateImplementationDetails>`), and one that
        // stays. Cleanup removes the first two, so the third keeps the name.
        let mut assembly = load_sample("packers/confuserex/1.6.0/original.exe").into_assembly();
        ClassBuilder::new("Twin")
            .namespace("Repairs")
            .static_field("data", TypeSignature::I4)
            .build(&mut assembly)
            .unwrap();
        TypeDefBuilder::new()
            .name("Twin")
            .namespace("Repairs")
            .build(&mut assembly)
            .unwrap();
        ClassBuilder::new("Twin")
            .namespace("Repairs")
            .static_field("data", TypeSignature::I4)
            .build(&mut assembly)
            .unwrap();
        let twins = CilObject::from_mem_with_validation(
            assembly.to_memory().unwrap(),
            ValidationConfig::analysis(),
        )
        .unwrap();
        let mut tokens: Vec<Token> = twins
            .types()
            .iter()
            .filter(|entry| entry.value().namespace == "Repairs")
            .map(|entry| *entry.key())
            .collect();
        tokens.sort();
        assert_eq!(tokens.len(), 3);
        let emptied = twins.types().get(&tokens[0]).unwrap();

        let mut request = CleanupRequest::with_settings(true, true);
        for (_, field) in emptied.fields.iter() {
            request.add_field(field.token);
        }
        let mut assembly = twins.into_assembly();
        let ctx = AnalysisContext::new(Arc::new(CallGraph::new()));
        apply_repairs(&mut assembly, &mut request, &ctx);
        assembly.add_cleanup(&request);
        let repaired = CilObject::from_mem_with_validation(
            assembly.to_memory().unwrap(),
            ValidationConfig::analysis(),
        )
        .unwrap();

        let names: Vec<String> = repaired
            .types()
            .iter()
            .filter(|entry| entry.value().namespace == "Repairs")
            .map(|entry| entry.value().name.clone())
            .collect();
        assert_eq!(names, ["Twin"]);
    }

    #[test]
    fn removing_a_duplicate_surviving_code_names_is_refused() {
        // The regression this repair once had: the duplicates removed though the entry point
        // reads their fields. The writer refuses to leave those reads dangling.
        let original = load_sample("packers/bitmono/0.45.0/bitmono_maximum.exe");
        let mut request = CleanupRequest::new();
        propose_removals(&original, &mut request);

        let mut assembly = original.into_assembly();
        assembly.add_cleanup(&request);
        let err = assembly.to_memory().unwrap_err();
        assert!(matches!(err, Error::DanglingReference { .. }), "{err}");
    }
}

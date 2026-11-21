//! Keeping an assembly's own Portable PDB tables true to the methods a change set edits.
//!
//! An assembly may hold Portable PDB tables in its own `#~` stream (rather than in a `.pdb`
//! file or an embedded PDB). Their rows describe methods by number and by IL offset:
//!
//! - `MethodDebugInformation` holds one row per MethodDef, in MethodDef order (the format
//!   allows the table to be empty, or that), with the method's sequence points;
//! - `LocalScope` rows name their method and an IL range, and own runs of `LocalVariable`
//!   and `LocalConstant` rows;
//! - `StateMachineMethod` names a MoveNext method and its kickoff method;
//! - `CustomDebugInformation` names its parent, a method or a scope or local among others.
//!
//! A change set that deletes a method, replaces its body or adds one leaves those rows
//! describing what is no longer there. [`follow_method_changes`] adds the change operations
//! that keep them true, before the writer runs:
//!
//! - a deleted method's `MethodDebugInformation` row goes with it, so both tables shift
//!   alike; its scopes (with their locals), its state machine rows and the custom debug
//!   information on it or on its scopes and locals go too;
//! - a replaced body's sequence points, scopes (with their locals) and custom debug
//!   information described IL that is gone: its `MethodDebugInformation` row is emptied, the
//!   rest removed; its state machine rows name methods, not IL, and stay;
//! - a method the change set adds gets an empty `MethodDebugInformation` row, so the table
//!   keeps one row per method.
//!
//! Only the input's rows are followed: a row the change set itself adds that names a
//! method it deletes is a contradiction the writer reports
//! ([`crate::Error::DanglingReference`]).
//!
//! The writer applies the same rules to the Portable PDB an image embeds
//! (`writer::pdb`), with [`replaced_method_bodies`] deciding which bodies were replaced.

use std::collections::{HashMap, HashSet};

use crate::{
    cilassembly::{changes::AssemblyChanges, CilAssembly, Operation, TableModifications},
    metadata::{
        tables::{
            CustomDebugInformationRaw, LocalScopeRaw, MemberList, MethodDebugInformationRaw,
            MethodDefRaw, StateMachineMethodRaw, TableDataOwned, TableId,
        },
        token::Token,
    },
    Result,
};

/// The input MethodDef rows whose bodies `changes` replace: a row whose latest update gives
/// it another RVA than the input's (a placeholder for a body the change stores, or another
/// body). A row the changes insert is new, not replaced.
pub fn replaced_method_bodies(assembly: &CilAssembly, changes: &AssemblyChanges) -> HashSet<u32> {
    let mut replaced = HashSet::new();
    let view = assembly.view();
    let Some(original) = view
        .tables()
        .and_then(|tables| tables.table::<MethodDefRaw>())
    else {
        return replaced;
    };
    let original_rva = |rid: u32| original.get(rid).ok().flatten().map(|row| row.rva);
    match changes.get_table_modifications(TableId::MethodDef) {
        Some(TableModifications::Sparse {
            operations,
            inserted_rows,
            ..
        }) => {
            // Operations are in timestamp order: the last update of a row is its state
            let mut latest: HashMap<u32, u32> = HashMap::new();
            for operation in operations {
                if let Operation::Update(rid, TableDataOwned::MethodDef(row)) = &operation.operation
                {
                    latest.insert(*rid, row.rva);
                }
            }
            for (rid, rva) in latest {
                if !inserted_rows.contains(&rid) && original_rva(rid).is_some_and(|old| old != rva)
                {
                    replaced.insert(rid);
                }
            }
        }
        Some(TableModifications::Replaced(rows)) => {
            for (index, row) in rows.iter().enumerate() {
                let (Ok(rid), TableDataOwned::MethodDef(row)) =
                    (u32::try_from(index.saturating_add(1)), row)
                else {
                    continue;
                };
                if original_rva(rid).is_some_and(|old| old != row.rva) {
                    replaced.insert(rid);
                }
            }
        }
        None => {}
    }
    replaced
}

/// The rows a change set deletes from `table` and the rows it inserts, by rid.
fn deleted_and_inserted(changes: &AssemblyChanges, table: TableId) -> (HashSet<u32>, HashSet<u32>) {
    match changes.get_table_modifications(table) {
        Some(TableModifications::Sparse {
            deleted_rows,
            inserted_rows,
            ..
        }) => (deleted_rows.clone(), inserted_rows.clone()),
        _ => (HashSet::new(), HashSet::new()),
    }
}

/// What [`follow_method_changes`] does, decided against the input before any edit.
#[derive(Default)]
struct Plan {
    /// `MethodDebugInformation` rows to empty, as they are to be written.
    emptied: Vec<MethodDebugInformationRaw>,
    /// Rows to remove, by table and rid.
    removed: Vec<(TableId, u32)>,
    /// Empty `MethodDebugInformation` rows to add.
    added: u32,
}

/// Adds the change operations that keep the assembly's own Portable PDB tables true to the
/// methods its change set deletes, replaces the bodies of and adds (see the module
/// documentation). A second call removes and adds nothing more; it may state an emptied
/// `MethodDebugInformation` row again, which writes the same row.
///
/// # Errors
///
/// When a change operation cannot be made.
pub fn follow_method_changes(assembly: &mut CilAssembly) -> Result<()> {
    let (deleted, inserted) = deleted_and_inserted(assembly.changes(), TableId::MethodDef);
    let replaced = replaced_method_bodies(assembly, assembly.changes());
    if deleted.is_empty() && inserted.is_empty() && replaced.is_empty() {
        return Ok(());
    }

    let plan = {
        let view = assembly.view();
        let Some(tables) = view.tables() else {
            return Ok(());
        };
        let changes = assembly.changes();
        let gone = |table: TableId, rid: u32| changes.is_row_deleted(table, rid);
        let mut plan = Plan::default();

        // MethodDebugInformation: one row per method, when the table has rows at all.
        let debug_rows = tables.table_row_count(TableId::MethodDebugInformation);
        if let Some(debug) = tables.table::<MethodDebugInformationRaw>() {
            for &rid in &deleted {
                if rid <= debug_rows && !gone(TableId::MethodDebugInformation, rid) {
                    plan.removed.push((TableId::MethodDebugInformation, rid));
                }
            }
            for &rid in replaced.difference(&deleted) {
                if let Some(row) = debug.get(rid).ok().flatten() {
                    if row.document != 0 || row.sequence_points != 0 {
                        plan.emptied.push(MethodDebugInformationRaw {
                            document: 0,
                            sequence_points: 0,
                            ..row
                        });
                    }
                }
            }
        }

        // The scopes of deleted and replaced methods, with the locals they own.
        let undescribed: HashSet<u32> = deleted.union(&replaced).copied().collect();
        let mut scopes: HashSet<u32> = HashSet::new();
        let mut variables: HashSet<u32> = HashSet::new();
        let mut constants: HashSet<u32> = HashSet::new();
        if let Some(table) = tables.table::<LocalScopeRaw>() {
            let variable_runs = tables.member_ranges(MemberList::LocalScopeVariables);
            let constant_runs = tables.member_ranges(MemberList::LocalScopeConstants);
            for scope in table.iter().filter_map(std::result::Result::ok) {
                if !undescribed.contains(&scope.method) {
                    continue;
                }
                scopes.insert(scope.rid);
                variables.extend(tables.member_rids(&variable_runs, scope.rid));
                constants.extend(tables.member_rids(&constant_runs, scope.rid));
            }
        }
        for (table, rows) in [
            (TableId::LocalScope, &scopes),
            (TableId::LocalVariable, &variables),
            (TableId::LocalConstant, &constants),
        ] {
            plan.removed.extend(
                rows.iter()
                    .filter(|&&rid| !gone(table, rid))
                    .map(|&rid| (table, rid)),
            );
        }

        // State machines naming a deleted method.
        if let Some(table) = tables.table::<StateMachineMethodRaw>() {
            for row in table.iter().filter_map(std::result::Result::ok) {
                if (deleted.contains(&row.move_next_method)
                    || deleted.contains(&row.kickoff_method))
                    && !gone(TableId::StateMachineMethod, row.rid)
                {
                    plan.removed.push((TableId::StateMachineMethod, row.rid));
                }
            }
        }

        // Custom debug information on what goes, or on a method whose body is replaced.
        if let Some(table) = tables.table::<CustomDebugInformationRaw>() {
            for row in table.iter().filter_map(std::result::Result::ok) {
                let parent = row.parent.row;
                let orphaned = match row.parent.tag {
                    TableId::MethodDef => undescribed.contains(&parent),
                    TableId::LocalScope => scopes.contains(&parent),
                    TableId::LocalVariable => variables.contains(&parent),
                    TableId::LocalConstant => constants.contains(&parent),
                    _ => false,
                };
                if orphaned && !gone(TableId::CustomDebugInformation, row.rid) {
                    plan.removed
                        .push((TableId::CustomDebugInformation, row.rid));
                }
            }
        }

        // Added methods: as many empty MethodDebugInformation rows as keep one per method.
        if debug_rows > 0 {
            let methods = tables
                .table_row_count(TableId::MethodDef)
                .saturating_sub(u32::try_from(deleted.len()).unwrap_or(u32::MAX))
                .saturating_add(u32::try_from(inserted.len()).unwrap_or(u32::MAX));
            let (debug_deleted, debug_inserted) =
                deleted_and_inserted(changes, TableId::MethodDebugInformation);
            let planned = plan
                .removed
                .iter()
                .filter(|(table, _)| *table == TableId::MethodDebugInformation)
                .count();
            let debug = debug_rows
                .saturating_sub(
                    u32::try_from(debug_deleted.len().saturating_add(planned)).unwrap_or(u32::MAX),
                )
                .saturating_add(u32::try_from(debug_inserted.len()).unwrap_or(u32::MAX));
            plan.added = methods.saturating_sub(debug);
        }
        plan
    };

    for row in plan.emptied {
        let rid = row.rid;
        assembly.table_row_update(
            TableId::MethodDebugInformation,
            rid,
            TableDataOwned::MethodDebugInformation(row),
        )?;
    }
    for (table, rid) in plan.removed {
        assembly.table_row_remove(table, rid)?;
    }
    for _ in 0..plan.added {
        assembly.table_row_add(
            TableId::MethodDebugInformation,
            TableDataOwned::MethodDebugInformation(MethodDebugInformationRaw {
                rid: 0,
                token: Token::from_parts(TableId::MethodDebugInformation, 0),
                offset: 0,
                document: 0,
                sequence_points: 0,
            }),
        )?;
    }
    Ok(())
}

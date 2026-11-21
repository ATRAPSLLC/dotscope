//! Shared helper functions for the cleanup module.
//!
//! These small utilities are used across multiple cleanup submodules to
//! reduce code duplication for common patterns like safe row removal and
//! candidate pruning. List ranges (which rows a TypeDef, MethodDef or map row
//! owns) come from [`TablesHeader::member_ranges`](crate::metadata::streams::TablesHeader::member_ranges)
//! and [`TablesHeader::member_rids`](crate::metadata::streams::TablesHeader::member_rids).

use std::collections::{BTreeSet, HashSet};

use crate::{
    cilassembly::{changes::METHOD_BODY_PLACEHOLDER_BASE, CilAssembly},
    metadata::{
        method::MethodBody,
        tables::{MethodDefRaw, TableId},
    },
};

/// Attempts to remove a table row, logging a debug message on failure.
pub fn try_remove(assembly: &mut CilAssembly, table_id: TableId, rid: u32) -> bool {
    match assembly.table_row_remove(table_id, rid) {
        Ok(()) => true,
        Err(e) => {
            log::debug!("cleanup: failed to remove {table_id:?} RID {rid}: {e}");
            false
        }
    }
}

/// Removes entries from `candidates` that are not in `alive`, in descending RID order.
///
/// Returns (count_removed, set_of_deleted_rids).
pub fn remove_candidates_not_alive(
    assembly: &mut CilAssembly,
    table_id: TableId,
    candidates: &BTreeSet<u32>,
    alive: &HashSet<u32>,
) -> (usize, HashSet<u32>) {
    let mut removed: usize = 0;
    let mut deleted_rids = HashSet::new();
    for &rid in candidates.iter().rev() {
        if !alive.contains(&rid) && try_remove(assembly, table_id, rid) {
            removed = removed.saturating_add(1);
            deleted_rids.insert(rid);
        }
    }
    (removed, deleted_rids)
}

/// Resolves a method's body bytes and invokes the callback.
///
/// Handles both original (RVA-based) and regenerated (placeholder) methods.
/// The callback receives `(body_bytes, base_rva)`.
pub fn with_method_body(
    assembly: &CilAssembly,
    effective_rva: u32,
    callback: &mut impl FnMut(&[u8], usize),
) {
    if effective_rva >= METHOD_BODY_PLACEHOLDER_BASE {
        if let Some(body_bytes) = assembly.changes().get_method_body(effective_rva) {
            callback(body_bytes, 0);
        }
    } else {
        if let Ok(slice) = assembly
            .view()
            .file()
            .section_bounded(effective_rva as usize)
        {
            callback(slice, effective_rva as usize);
        }
    }
}

/// Extracts the `LocalVarSigTok` from a method body's header (if present).
///
/// Returns the `StandAloneSig` RID if the method body has a local variable
/// signature token, or `None` otherwise.
pub fn extract_local_var_sig_rid(data: &[u8]) -> Option<u32> {
    MethodBody::from(data).ok()?.local_var_sig_rid()
}

/// Returns true if the given MethodDef row is a `.cctor` (static constructor).
///
/// This is the raw-table-level equivalent of [`Method::is_cctor()`](crate::metadata::method::Method::is_cctor) for code
/// that operates on RIDs and [`CilAssembly`] rather than resolved method objects.
///
/// `.cctor` methods are invoked implicitly by the runtime on first type access,
/// not via explicit IL instructions. They must be protected from cascade removal
/// because they don't appear in method body token scans.
pub fn is_cctor_method(assembly: &CilAssembly, method_rid: u32) -> bool {
    let view = assembly.view();
    let Some(tables) = view.tables() else {
        return false;
    };
    let Some(method_table) = tables.table::<MethodDefRaw>() else {
        return false;
    };
    let Some(row) = method_table.get(method_rid).ok().flatten() else {
        return false;
    };
    let Some(strings) = view.strings() else {
        return false;
    };
    strings
        .get(row.name as usize)
        .ok()
        .is_some_and(|name| name == ".cctor")
}

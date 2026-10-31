//! Shared helper functions for the cleanup module.
//!
//! These small utilities are used across multiple cleanup submodules to
//! reduce code duplication for common patterns like list-range computation,
//! safe row removal, and candidate pruning.

use std::collections::{BTreeSet, HashSet};

use crate::{
    cilassembly::{changes::METHOD_BODY_PLACEHOLDER_BASE, CilAssembly},
    metadata::{
        method::MethodBody,
        tables::{MethodDefRaw, TableId},
        token::Token,
    },
};

/// Computes the RID range `[start..end)` for a metadata list owned by a parent row.
///
/// Many metadata tables use list-style ownership where the parent row contains
/// a `_list` field pointing to the first child, and the next parent's `_list`
/// field indicates the end. This helper encapsulates that pattern.
pub(super) fn list_range(
    owner_rid: u32,
    owner_count: u32,
    child_count: u32,
    get_list_start: impl Fn(u32) -> Option<u32>,
) -> std::ops::Range<u32> {
    let sentinel = child_count.saturating_add(1);
    let start = get_list_start(owner_rid).unwrap_or(sentinel);
    let end = if owner_rid < owner_count {
        get_list_start(owner_rid.saturating_add(1)).unwrap_or(sentinel)
    } else {
        sentinel
    };
    start..end
}

/// Attempts to remove a table row, logging a debug message on failure.
pub(super) fn try_remove(assembly: &mut CilAssembly, table_id: TableId, rid: u32) -> bool {
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
pub(super) fn remove_candidates_not_alive(
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
pub(crate) fn with_method_body(
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
pub(crate) fn extract_local_var_sig_rid(data: &[u8]) -> Option<u32> {
    let body = MethodBody::from(data).ok()?;
    if body.local_var_sig_token != 0 {
        let sig_token = Token::new(body.local_var_sig_token);
        if sig_token.is_table(TableId::StandAloneSig) {
            return Some(sig_token.row());
        }
    }
    None
}

/// Returns true if the given MethodDef row is a `.cctor` (static constructor).
///
/// This is the raw-table-level equivalent of [`Method::is_cctor()`] for code
/// that operates on RIDs and [`CilAssembly`] rather than resolved method objects.
///
/// `.cctor` methods are invoked implicitly by the runtime on first type access,
/// not via explicit IL instructions. They must be protected from cascade removal
/// because they don't appear in method body token scans.
pub(crate) fn is_cctor_method(assembly: &CilAssembly, method_rid: u32) -> bool {
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

#[cfg(test)]
mod tests {
    use crate::cilassembly::cleanup::utils::list_range;

    #[test]
    fn test_list_range_middle() {
        // Owner RID 2 of 5 owners, 20 children
        let range = list_range(2, 5, 20, |rid| match rid {
            2 => Some(5),
            3 => Some(8),
            _ => None,
        });
        assert_eq!(range, 5..8);
    }

    #[test]
    fn test_list_range_last_owner() {
        // Owner RID 5 of 5 owners, 20 children
        let range = list_range(5, 5, 20, |rid| match rid {
            5 => Some(18),
            _ => None,
        });
        assert_eq!(range, 18..21);
    }

    #[test]
    fn test_list_range_no_next_owner() {
        // Owner RID 2 of 5, but next owner has no entry
        let range = list_range(2, 5, 20, |rid| match rid {
            2 => Some(10),
            _ => None,
        });
        assert_eq!(range, 10..21);
    }
}

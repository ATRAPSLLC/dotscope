//! The writer's identity: an assembly written back unchanged holds what it held.

use crate::{
    cilassembly::CilAssembly,
    metadata::tables::FieldRvaRaw,
    testkit::{
        corpus::{CorpusCheck, CorpusItem},
        dump::CanonicalDump,
    },
    CilAssemblyView,
};

/// How many differences a written assembly reports before it counts the rest.
const LISTED_DIFFERENCES: usize = 5;

/// Every assembly written back without a change has the canonical dump it was read with.
/// A fixture malformed by design, which the manifest has rejected, is not written.
///
/// An assembly with field data the reader cannot read (past its section's VirtualSize, where
/// the runtimes read different bytes) cannot be written: the write must fail naming such a
/// field.
pub struct WritesBackUnchanged;

impl CorpusCheck for WritesBackUnchanged {
    fn id(&self) -> &'static str {
        "writer.identity"
    }

    fn run(&self, item: &CorpusItem) -> Vec<String> {
        if item.fixture.reject.is_some() {
            return Vec::new();
        }
        let Ok(bytes) = item.bytes() else {
            return Vec::new();
        };
        let view = match CilAssemblyView::from_mem(bytes) {
            Ok(view) => view,
            Err(error) => return vec![format!("does not read: {error}")],
        };
        let before = CanonicalDump::of(&view);
        let undefined: Vec<String> = view
            .tables()
            .and_then(|tables| tables.table::<FieldRvaRaw>())
            .into_iter()
            .flat_map(|table| table.iter().flatten())
            .filter(|row| {
                before
                    .entries()
                    .get(&format!("FieldRVA[{}].data", row.rid))
                    .is_some_and(|data| data.starts_with("unreadable"))
            })
            .map(|row| format!("for field {}", row.field))
            .collect();
        let written = match (CilAssembly::new(view).to_memory(), undefined.is_empty()) {
            (Ok(written), true) => written,
            (Err(error), true) => return vec![format!("does not write: {error}")],
            (Err(error), false) => {
                let error = error.to_string();
                return if undefined.iter().any(|field| error.contains(field.as_str())) {
                    Vec::new()
                } else {
                    vec![format!(
                        "its field data is unreadable, and the write fails otherwise: {error}"
                    )]
                };
            }
            (Ok(_), false) => {
                return vec![format!(
                    "writes field data it cannot read ({})",
                    undefined.join(", ")
                )]
            }
        };
        let after = match CilAssemblyView::from_mem(written) {
            Ok(view) => CanonicalDump::of(&view),
            Err(error) => return vec![format!("written, does not read back: {error}")],
        };
        let differences = before.diff(&after);
        let more = differences.len().saturating_sub(LISTED_DIFFERENCES);
        let mut findings: Vec<String> = differences.into_iter().take(LISTED_DIFFERENCES).collect();
        if more > 0 {
            findings.push(format!("{more} more differences"));
        }
        findings
    }
}

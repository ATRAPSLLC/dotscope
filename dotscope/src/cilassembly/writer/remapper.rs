//! RID remapping for table row deletions.
//!
//! When rows are deleted from metadata tables, all subsequent rows shift down to fill
//! the gaps. This module provides the [`RidRemapper`] which calculates the new RIDs
//! and applies remapping to all cross-table references during the write phase.
//!
//! # The Problem
//!
//! When `table_row_remove()` deletes row 5 from a 10-row table:
//! - Rows 1-4 remain unchanged
//! - Row 5 is removed
//! - Rows 6-10 shift down to become rows 5-9
//!
//! But other tables still reference the OLD RIDs:
//! - `TypeDef.method_list` might point to method RID 7 (now RID 6)
//! - `CustomAttribute.parent` might point to `0x06000007` (now `0x06000006`)
//!
//! # Solution
//!
//! The remapper:
//! 1. Builds a mapping from old RIDs to new RIDs for each table with deletions
//! 2. During table serialization, applies this mapping to all reference fields
//!
//! # Algorithm
//!
//! For a table with deletions, iterate through all original RIDs:
//! - If deleted: skip (don't increment new RID counter)
//! - If not deleted: map old RID → new RID, increment counter
//!
//! This handles multiple deletions correctly since we count all gaps.
//!
//! # Example
//!
//! Original table with 10 rows, delete rows 3 and 7:
//! ```text
//! Old RID:  1  2  3  4  5  6  7  8  9  10
//! Deleted:        ✗           ✗
//! New RID:  1  2  -  3  4  5  -  6  7  8
//!
//! Remapping: 4→3, 5→4, 6→5, 8→6, 9→7, 10→8
//! ```
//!
//! # References and list starts
//!
//! A deleted row has no new RID. A list column (`TypeDef.FieldList`, `MethodDef.ParamList`
//! and the like) that starts at one starts at the next surviving row instead, its
//! continuation, since the list it opens has lost that row. Any other reference to a deleted
//! row is dangling: the write fails with [`Error::DanglingReference`], or writes a null
//! reference under [`DanglingPolicy::Null`]. It is never retargeted.
//!
//! # References
//!
//! - ECMA-335 §II.22 - Metadata logical format
//! - ECMA-335 §II.24.2.6 - Coded indices

use std::collections::{HashMap, HashSet};

use crate::{
    cilassembly::{AssemblyChanges, DanglingPolicy, TableModifications},
    metadata::{
        tables::{
            AssemblyOsRaw, AssemblyProcessorRaw, AssemblyRaw, AssemblyRefOsRaw,
            AssemblyRefProcessorRaw, AssemblyRefRaw, ClassLayoutRaw, CodedIndex, ConstantRaw,
            CustomAttributeRaw, CustomDebugInformationRaw, DeclSecurityRaw, DocumentRaw, EncLogRaw,
            EncMapRaw, EventMapRaw, EventPtrRaw, EventRaw, ExportedTypeRaw, FieldLayoutRaw,
            FieldMarshalRaw, FieldPtrRaw, FieldRaw, FieldRvaRaw, FileRaw,
            GenericParamConstraintRaw, GenericParamRaw, ImplMapRaw, ImportScopeRaw,
            InterfaceImplRaw, LocalConstantRaw, LocalScopeRaw, LocalVariableRaw,
            ManifestResourceRaw, MemberRefRaw, MethodDebugInformationRaw, MethodDefRaw,
            MethodImplRaw, MethodPtrRaw, MethodSemanticsRaw, MethodSpecRaw, ModuleRaw,
            ModuleRefRaw, NestedClassRaw, ParamPtrRaw, ParamRaw, PropertyMapRaw, PropertyPtrRaw,
            PropertyRaw, StandAloneSigRaw, StateMachineMethodRaw, TableDataOwned, TableId,
            TypeDefRaw, TypeRefRaw, TypeSpecRaw,
        },
        token::Token,
    },
    Error, Referrer, Result,
};

/// Remaps RIDs after row deletions to maintain valid cross-table references.
///
/// When rows are deleted from metadata tables, all subsequent rows shift down.
/// This struct tracks those shifts and provides methods to remap references
/// in other tables that point to the shifted rows.
///
/// # Building the Remapper
///
/// The remapper is built from `AssemblyChanges` before writing tables:
///
/// ```no_run
/// let remapper = RidRemapper::from_changes(&changes, &original_counts);
/// ```
///
/// # Applying Remapping
///
/// During table serialization, call `remap_references` on each row:
///
/// ```no_run
/// row.remap_references(&remapper)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Default)]
pub struct RidRemapper {
    /// For each table with deletions: the new RID of every surviving row whose RID changes.
    refs: HashMap<TableId, HashMap<u32, u32>>,

    /// For each table with deletions: where a list starting at a deleted row, or one past
    /// the last row, starts once the deletions are made. Only RIDs that change are stored.
    list_starts: HashMap<TableId, HashMap<u32, u32>>,

    /// Tables that have any deletions (for quick lookup)
    tables_with_deletions: HashSet<TableId>,

    /// For each table with deletions: the set of deleted RIDs
    ///
    /// Used to filter out deleted RIDs when remapping type tokens in signatures,
    /// since deleted types shouldn't be remapped to other types.
    deleted_rids: HashMap<TableId, HashSet<u32>>,

    /// For each table the writer reorders into the sort order the format
    /// requires: the RID a row would be written at once deletions are
    /// accounted for → the RID it is written at. Only tables whose order
    /// actually changes appear. Applied after the deletion shift.
    sort_orders: HashMap<TableId, HashMap<u32, u32>>,

    /// What a reference to a deleted row becomes.
    dangling: DanglingPolicy,
}

impl RidRemapper {
    /// Creates an empty remapper with no mappings.
    ///
    /// Use this when there are no deletions in any table.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Returns `true` if no row changes position: nothing was deleted and no
    /// table was reordered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tables_with_deletions.is_empty() && self.sort_orders.is_empty()
    }

    /// Returns `true` if the specified table has any deletions.
    #[must_use]
    pub fn has_deletions(&self, table_id: TableId) -> bool {
        self.tables_with_deletions.contains(&table_id)
    }

    /// Builds a remapper from assembly changes.
    ///
    /// Examines all table modifications to find deletions, then calculates
    /// the new RID for each surviving row.
    ///
    /// # Arguments
    ///
    /// * `changes` - The assembly changes containing table modifications
    /// * `original_counts` - Map from TableId to original row count (before modifications)
    /// * `dangling` - What a reference to a deleted row becomes
    ///
    /// # Returns
    ///
    /// A `RidRemapper` with mappings for all tables that have deletions.
    #[must_use]
    pub fn from_changes(
        changes: &AssemblyChanges,
        original_counts: &HashMap<TableId, u32>,
        dangling: DanglingPolicy,
    ) -> Self {
        let mut refs = HashMap::new();
        let mut list_starts = HashMap::new();
        let mut tables_with_deletions = HashSet::new();
        let mut deleted_rids = HashMap::new();

        for (table_id, table_mods) in &changes.table_changes {
            if let TableModifications::Sparse { deleted_rows, .. } = table_mods {
                if deleted_rows.is_empty() {
                    continue;
                }

                tables_with_deletions.insert(*table_id);
                deleted_rids.insert(*table_id, deleted_rows.clone());

                let original_count = original_counts.get(table_id).copied().unwrap_or(0);
                let (table_refs, table_list_starts) =
                    Self::calculate_remapping(deleted_rows, original_count);

                if !table_refs.is_empty() {
                    refs.insert(*table_id, table_refs);
                }
                if !table_list_starts.is_empty() {
                    list_starts.insert(*table_id, table_list_starts);
                }
            }
        }

        Self {
            refs,
            list_starts,
            tables_with_deletions,
            deleted_rids,
            sort_orders: HashMap::new(),
            dangling,
        }
    }

    /// Records the order a sorted table is written in.
    ///
    /// `rows` holds each row the table writes, in the order it would write
    /// them otherwise: the RID the row is known by (its original RID, or the
    /// RID it was inserted at) and its [sort key](crate::metadata::tables::RowWritable::sort_key).
    /// The rows are stably sorted by key, so rows sharing a key keep their
    /// order, and every reference to a row is then remapped to where it lands.
    ///
    /// Returns the indices into `rows` in the order they are to be written.
    pub fn set_sort_order(&mut self, table_id: TableId, rows: &[(u32, (u32, u32))]) -> Vec<usize> {
        let mut order: Vec<usize> = (0..rows.len()).collect();
        order.sort_by_key(|&index| rows.get(index).map(|(_, key)| *key));

        let mut moved = HashMap::new();
        for (position, &index) in order.iter().enumerate() {
            let Some(&(rid, _)) = rows.get(index) else {
                continue;
            };
            let Ok(position) = u32::try_from(position) else {
                continue;
            };
            let written_at = position.saturating_add(1);
            let otherwise_at = self.shift(table_id, rid);
            if written_at != otherwise_at {
                moved.insert(otherwise_at, written_at);
            }
        }
        if !moved.is_empty() {
            self.sort_orders.insert(table_id, moved);
        }
        order
    }

    /// Whether the writer reorders `table_id` to sort it.
    #[must_use]
    pub fn is_reordered(&self, table_id: TableId) -> bool {
        self.sort_orders.contains_key(&table_id)
    }

    /// The RID a surviving row of `table_id` known as `old_rid` has once deletions are
    /// accounted for, before any reordering.
    fn shift(&self, table_id: TableId, old_rid: u32) -> u32 {
        self.refs
            .get(&table_id)
            .and_then(|map| map.get(&old_rid))
            .copied()
            .unwrap_or(old_rid)
    }

    /// Calculates the RID remapping for a single table.
    ///
    /// # Algorithm
    ///
    /// Iterate through all original RIDs (1..=original_count):
    /// - If the RID is in `deleted_rows`, skip it (don't increment new_rid)
    /// - Otherwise, if old_rid != new_rid, record the mapping
    /// - Increment new_rid for each surviving row
    ///
    /// Also tracks the "continuation" for deleted rows - the new RID of the first
    /// surviving row after a deleted row. This is needed for "list start" fields
    /// like param_list, method_list, and field_list.
    ///
    /// # Arguments
    ///
    /// * `deleted_rows` - Set of RIDs that have been deleted
    /// * `original_count` - Total number of rows before deletions
    ///
    /// # Returns
    ///
    /// The new RID of each surviving row that changes, and the continuation of each
    /// deleted row and of one past the last row, where it differs.
    fn calculate_remapping(
        deleted_rows: &HashSet<u32>,
        original_count: u32,
    ) -> (HashMap<u32, u32>, HashMap<u32, u32>) {
        let mut remap = HashMap::new();
        let mut continuations = HashMap::new();
        let mut new_rid = 1u32;

        // First pass: calculate new RIDs for surviving rows
        let mut surviving_rids: Vec<(u32, u32)> = Vec::new();
        for old_rid in 1..=original_count {
            if deleted_rows.contains(&old_rid) {
                continue;
            }
            surviving_rids.push((old_rid, new_rid));
            if old_rid != new_rid {
                remap.insert(old_rid, new_rid);
            }
            new_rid = new_rid.saturating_add(1);
        }

        // Second pass: for deleted rows, find the "continuation" RID
        // This is the new RID of the first surviving row after the deleted row
        let final_new_rid = new_rid; // One past the last new RID
        for old_rid in 1..=original_count {
            if !deleted_rows.contains(&old_rid) {
                continue; // Skip surviving rows
            }

            // Find the first surviving row after this deleted row
            let continuation = surviving_rids
                .iter()
                .find(|(orig, _)| *orig > old_rid)
                .map_or(final_new_rid, |(_, new)| *new); // If no surviving row after, point past end

            if continuation != old_rid {
                continuations.insert(old_rid, continuation);
            }
        }

        // Third pass: handle the "continuation" value (one past the original end)
        // In .NET, tables like MethodDef use param_list/field_list/method_list values
        // that can point one past the end of the table to indicate "no items".
        // When rows are deleted, this continuation value must also be remapped.
        let old_continuation = original_count.saturating_add(1);
        if old_continuation != final_new_rid {
            continuations.insert(old_continuation, final_new_rid);
        }

        (remap, continuations)
    }

    /// The RID a reference to row `old_rid` of `target_table` has in the output.
    ///
    /// # Arguments
    ///
    /// * `referrer` - What holds the reference, for the error naming it
    /// * `target_table` - The table that the RID references
    /// * `old_rid` - The original RID value
    ///
    /// # Returns
    ///
    /// The row's RID once deletions and reordering are made; 0 stays 0. A deleted row
    /// becomes 0 under [`DanglingPolicy::Null`].
    ///
    /// # Errors
    ///
    /// [`Error::DanglingReference`] when the row is deleted, under [`DanglingPolicy::Error`].
    pub fn reference(
        &self,
        referrer: Referrer,
        target_table: TableId,
        old_rid: u32,
    ) -> Result<u32> {
        if old_rid == 0 {
            return Ok(0);
        }
        if self
            .deleted_rids
            .get(&target_table)
            .is_some_and(|deleted| deleted.contains(&old_rid))
        {
            let target = Token::from_parts(target_table, old_rid);
            return match self.dangling {
                DanglingPolicy::Error => Err(Error::DanglingReference { referrer, target }),
                DanglingPolicy::Null => {
                    log::warn!(
                        "{referrer} names {target}, which the write deletes: written as null"
                    );
                    Ok(0)
                }
            };
        }

        let shifted = self.shift(target_table, old_rid);
        Ok(self
            .sort_orders
            .get(&target_table)
            .and_then(|map| map.get(&shifted))
            .copied()
            .unwrap_or(shifted))
    }

    /// The RID a list column starting at row `old_rid` of `target_table` has in the output.
    ///
    /// A list that started at a deleted row, or one past the last row, starts at the next
    /// surviving row: the rows it kept are the ones from there to the next list's start.
    #[must_use]
    pub fn list_start(&self, target_table: TableId, old_rid: u32) -> u32 {
        if old_rid == 0 {
            return 0;
        }
        self.list_starts
            .get(&target_table)
            .and_then(|map| map.get(&old_rid))
            .copied()
            .unwrap_or_else(|| self.shift(target_table, old_rid))
    }

    /// The new RID of every surviving row of `table_id` whose RID changes, for the tokens
    /// signature blobs hold; `None` if none does.
    #[must_use]
    pub fn surviving_remap(&self, table_id: TableId) -> Option<HashMap<u32, u32>> {
        self.refs.get(&table_id).cloned()
    }

    /// Remaps a coded index reference in place.
    ///
    /// # Arguments
    ///
    /// * `row` - The row holding the coded index
    /// * `column` - Its column, by its ECMA-335 name
    /// * `coded_index` - The coded index to remap
    ///
    /// # Errors
    ///
    /// As [`RidRemapper::reference`].
    pub fn remap_coded_index(
        &self,
        row: Token,
        column: &'static str,
        coded_index: &mut CodedIndex,
    ) -> Result<()> {
        if coded_index.row == 0 {
            return Ok(());
        }

        let table_id = coded_index.tag;
        let new_rid =
            self.reference(Referrer::Column { row, column }, table_id, coded_index.row)?;
        if new_rid != coded_index.row {
            coded_index.row = new_rid;
            coded_index.token = Token::from_parts(table_id, new_rid);
        }
        Ok(())
    }

    /// Returns the number of tables that have remappings.
    #[must_use]
    pub fn table_count(&self) -> usize {
        self.refs.len()
    }

    /// Returns the total number of RID remappings across all tables.
    #[must_use]
    pub fn total_remappings(&self) -> usize {
        self.refs.values().map(HashMap::len).sum()
    }

    /// How the tokens a method body or the CLI header holds are renumbered: every surviving
    /// row whose RID changes, and the deleted rows, which no token may name.
    #[must_use]
    pub fn token_remap(&self) -> TokenRemap {
        let mut map = HashMap::new();
        for (table_id, rid_map) in &self.refs {
            let table_byte = (*table_id as u32) << 24;
            for (&old_rid, &new_rid) in rid_map {
                if old_rid != new_rid {
                    map.insert(table_byte | old_rid, table_byte | new_rid);
                }
            }
        }
        let deleted = self
            .deleted_rids
            .iter()
            .flat_map(|(table_id, rids)| {
                let table_byte = (*table_id as u32) << 24;
                rids.iter().map(move |rid| table_byte | rid)
            })
            .collect();
        TokenRemap {
            map,
            deleted,
            dangling: self.dangling,
        }
    }
}

/// How a write renumbers the metadata tokens outside the tables: instruction operands, local
/// variable signatures, catch types and the entry point.
#[derive(Debug, Default)]
pub struct TokenRemap {
    /// Old token to new token, for every token that changes.
    map: HashMap<u32, u32>,
    /// The tokens of the rows the write deletes.
    deleted: HashSet<u32>,
    /// What a token naming a deleted row becomes.
    dangling: DanglingPolicy,
}

impl TokenRemap {
    /// A remap that renumbers `map`'s tokens and deletes `deleted`'s rows, for tests.
    #[cfg(test)]
    pub(crate) fn for_tests(map: &[(u32, u32)], deleted: &[u32], dangling: DanglingPolicy) -> Self {
        Self {
            map: map.iter().copied().collect(),
            deleted: deleted.iter().copied().collect(),
            dangling,
        }
    }

    /// Records that `old` is written as `new`, overriding the deletion shift.
    pub fn insert(&mut self, old: u32, new: u32) {
        self.map.insert(old, new);
    }

    /// Whether no token changes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty() && self.deleted.is_empty()
    }

    /// The number of tokens that change.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// The token `token` is written as.
    ///
    /// # Arguments
    ///
    /// * `referrer` - What holds the token, for the error naming it
    /// * `token` - The token as the input assembly has it
    ///
    /// # Errors
    ///
    /// [`Error::DanglingReference`] when it names a deleted row, under
    /// [`DanglingPolicy::Error`]. Under [`DanglingPolicy::Null`] it becomes the null token
    /// of its table.
    pub fn remap(&self, referrer: Referrer, token: u32) -> Result<u32> {
        if self.deleted.contains(&token) {
            let target = Token::new(token);
            return match self.dangling {
                DanglingPolicy::Error => Err(Error::DanglingReference { referrer, target }),
                DanglingPolicy::Null => {
                    log::warn!(
                        "{referrer} names {target}, which the write deletes: written as null"
                    );
                    Ok(token & 0xFF00_0000)
                }
            };
        }
        Ok(self.map.get(&token).copied().unwrap_or(token))
    }
}

/// Trait for remapping cross-table RID references in metadata table rows.
///
/// Each table type implements this to remap its specific reference fields
/// (both direct RID references and coded indices) when rows are deleted
/// from referenced tables.
///
/// This is the complement to `ResolvePlaceholders` - while that trait resolves
/// heap references, this trait handles table row references.
pub trait RemapReferences {
    /// Remaps all cross-table references in this row.
    ///
    /// # Arguments
    ///
    /// * `remapper` - The RID remapper containing old→new RID mappings
    ///
    /// # Errors
    ///
    /// [`Error::DanglingReference`] when a column names a row the write deletes.
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()>;
}

impl RemapReferences for TypeRefRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // ResolutionScope: Module, ModuleRef, AssemblyRef, TypeRef
        remapper.remap_coded_index(self.token, "ResolutionScope", &mut self.resolution_scope)?;
        Ok(())
    }
}

impl RemapReferences for TypeDefRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // Extends: TypeDef, TypeRef, TypeSpec
        remapper.remap_coded_index(self.token, "Extends", &mut self.extends)?;

        // FieldList: direct RID into Field table
        self.field_list = remapper.list_start(TableId::Field, self.field_list);

        // MethodList: direct RID into MethodDef table
        self.method_list = remapper.list_start(TableId::MethodDef, self.method_list);
        Ok(())
    }
}

impl RemapReferences for MethodDefRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // ParamList: direct RID into Param table
        self.param_list = remapper.list_start(TableId::Param, self.param_list);
        Ok(())
    }
}

impl RemapReferences for InterfaceImplRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // Class: direct RID into TypeDef table
        self.class = remapper.reference(
            Referrer::Column {
                row: self.token,
                column: "Class",
            },
            TableId::TypeDef,
            self.class,
        )?;

        // Interface: TypeDef, TypeRef, TypeSpec
        remapper.remap_coded_index(self.token, "Interface", &mut self.interface)?;
        Ok(())
    }
}

impl RemapReferences for MemberRefRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // Class: TypeDef, TypeRef, ModuleRef, MethodDef, TypeSpec
        remapper.remap_coded_index(self.token, "Class", &mut self.class)?;
        Ok(())
    }
}

impl RemapReferences for ConstantRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // Parent: Field, Param, Property
        remapper.remap_coded_index(self.token, "Parent", &mut self.parent)?;
        Ok(())
    }
}

impl RemapReferences for CustomAttributeRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // Parent: HasCustomAttribute (22 tables!)
        remapper.remap_coded_index(self.token, "Parent", &mut self.parent)?;

        // Constructor: MethodDef, MemberRef
        remapper.remap_coded_index(self.token, "Type", &mut self.constructor)?;
        Ok(())
    }
}

impl RemapReferences for FieldMarshalRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // Parent: Field, Param
        remapper.remap_coded_index(self.token, "Parent", &mut self.parent)?;
        Ok(())
    }
}

impl RemapReferences for DeclSecurityRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // Parent: TypeDef, MethodDef, Assembly
        remapper.remap_coded_index(self.token, "Parent", &mut self.parent)?;
        Ok(())
    }
}

impl RemapReferences for ClassLayoutRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // Parent: direct RID into TypeDef table
        self.parent = remapper.reference(
            Referrer::Column {
                row: self.token,
                column: "Parent",
            },
            TableId::TypeDef,
            self.parent,
        )?;
        Ok(())
    }
}

impl RemapReferences for FieldLayoutRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // Field: direct RID into Field table
        self.field = remapper.reference(
            Referrer::Column {
                row: self.token,
                column: "Field",
            },
            TableId::Field,
            self.field,
        )?;
        Ok(())
    }
}

impl RemapReferences for EventMapRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // Parent: direct RID into TypeDef table
        self.parent = remapper.reference(
            Referrer::Column {
                row: self.token,
                column: "Parent",
            },
            TableId::TypeDef,
            self.parent,
        )?;

        // EventList: direct RID into Event table
        self.event_list = remapper.list_start(TableId::Event, self.event_list);
        Ok(())
    }
}

impl RemapReferences for EventRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // EventType: TypeDef, TypeRef, TypeSpec
        remapper.remap_coded_index(self.token, "EventType", &mut self.event_type)?;
        Ok(())
    }
}

impl RemapReferences for PropertyMapRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // Parent: direct RID into TypeDef table
        self.parent = remapper.reference(
            Referrer::Column {
                row: self.token,
                column: "Parent",
            },
            TableId::TypeDef,
            self.parent,
        )?;

        // PropertyList: direct RID into Property table
        self.property_list = remapper.list_start(TableId::Property, self.property_list);
        Ok(())
    }
}

impl RemapReferences for MethodSemanticsRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // Method: direct RID into MethodDef table
        self.method = remapper.reference(
            Referrer::Column {
                row: self.token,
                column: "Method",
            },
            TableId::MethodDef,
            self.method,
        )?;

        // Association: Event, Property
        remapper.remap_coded_index(self.token, "Association", &mut self.association)?;
        Ok(())
    }
}

impl RemapReferences for MethodImplRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // Class: direct RID into TypeDef table
        self.class = remapper.reference(
            Referrer::Column {
                row: self.token,
                column: "Class",
            },
            TableId::TypeDef,
            self.class,
        )?;

        // MethodBody: MethodDef, MemberRef
        remapper.remap_coded_index(self.token, "MethodBody", &mut self.method_body)?;

        // MethodDeclaration: MethodDef, MemberRef
        remapper.remap_coded_index(
            self.token,
            "MethodDeclaration",
            &mut self.method_declaration,
        )?;
        Ok(())
    }
}

impl RemapReferences for ImplMapRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // MemberForwarded: Field, MethodDef
        remapper.remap_coded_index(self.token, "MemberForwarded", &mut self.member_forwarded)?;

        // ImportScope: direct RID into ModuleRef table
        self.import_scope = remapper.reference(
            Referrer::Column {
                row: self.token,
                column: "ImportScope",
            },
            TableId::ModuleRef,
            self.import_scope,
        )?;
        Ok(())
    }
}

impl RemapReferences for FieldRvaRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // Field: direct RID into Field table
        self.field = remapper.reference(
            Referrer::Column {
                row: self.token,
                column: "Field",
            },
            TableId::Field,
            self.field,
        )?;
        Ok(())
    }
}

impl RemapReferences for AssemblyRefRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) -> Result<()> {
        // AssemblyRef has no cross-table references, only heap refs
        Ok(())
    }
}

impl RemapReferences for ExportedTypeRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // Implementation: File, AssemblyRef, ExportedType
        remapper.remap_coded_index(self.token, "Implementation", &mut self.implementation)?;
        Ok(())
    }
}

impl RemapReferences for ManifestResourceRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // Implementation: File, AssemblyRef (ExportedType not valid here per spec)
        remapper.remap_coded_index(self.token, "Implementation", &mut self.implementation)?;
        Ok(())
    }
}

impl RemapReferences for NestedClassRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // NestedClass: direct RID into TypeDef table
        self.nested_class = remapper.reference(
            Referrer::Column {
                row: self.token,
                column: "NestedClass",
            },
            TableId::TypeDef,
            self.nested_class,
        )?;

        // EnclosingClass: direct RID into TypeDef table
        self.enclosing_class = remapper.reference(
            Referrer::Column {
                row: self.token,
                column: "EnclosingClass",
            },
            TableId::TypeDef,
            self.enclosing_class,
        )?;
        Ok(())
    }
}

impl RemapReferences for GenericParamRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // Owner: TypeDef, MethodDef
        remapper.remap_coded_index(self.token, "Owner", &mut self.owner)?;
        Ok(())
    }
}

impl RemapReferences for MethodSpecRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // Method: MethodDef, MemberRef
        remapper.remap_coded_index(self.token, "Method", &mut self.method)?;
        Ok(())
    }
}

impl RemapReferences for GenericParamConstraintRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // Owner: direct RID into GenericParam table
        self.owner = remapper.reference(
            Referrer::Column {
                row: self.token,
                column: "Owner",
            },
            TableId::GenericParam,
            self.owner,
        )?;

        // Constraint: TypeDef, TypeRef, TypeSpec
        remapper.remap_coded_index(self.token, "Constraint", &mut self.constraint)?;
        Ok(())
    }
}

impl RemapReferences for ModuleRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) -> Result<()> {
        Ok(())
    }
}

impl RemapReferences for FieldPtrRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // Field: direct RID into Field table
        self.field = remapper.reference(
            Referrer::Column {
                row: self.token,
                column: "Field",
            },
            TableId::Field,
            self.field,
        )?;
        Ok(())
    }
}

impl RemapReferences for FieldRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) -> Result<()> {
        Ok(())
    }
}

impl RemapReferences for MethodPtrRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // Method: direct RID into MethodDef table
        self.method = remapper.reference(
            Referrer::Column {
                row: self.token,
                column: "Method",
            },
            TableId::MethodDef,
            self.method,
        )?;
        Ok(())
    }
}

impl RemapReferences for ParamPtrRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // Param: direct RID into Param table
        self.param = remapper.reference(
            Referrer::Column {
                row: self.token,
                column: "Param",
            },
            TableId::Param,
            self.param,
        )?;
        Ok(())
    }
}

impl RemapReferences for ParamRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) -> Result<()> {
        Ok(())
    }
}

impl RemapReferences for StandAloneSigRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) -> Result<()> {
        Ok(())
    }
}

impl RemapReferences for EventPtrRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // Event: direct RID into Event table
        self.event = remapper.reference(
            Referrer::Column {
                row: self.token,
                column: "Event",
            },
            TableId::Event,
            self.event,
        )?;
        Ok(())
    }
}

impl RemapReferences for PropertyPtrRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // Property: direct RID into Property table
        self.property = remapper.reference(
            Referrer::Column {
                row: self.token,
                column: "Property",
            },
            TableId::Property,
            self.property,
        )?;
        Ok(())
    }
}

impl RemapReferences for PropertyRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) -> Result<()> {
        Ok(())
    }
}

impl RemapReferences for ModuleRefRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) -> Result<()> {
        Ok(())
    }
}

impl RemapReferences for TypeSpecRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) -> Result<()> {
        Ok(())
    }
}

impl RemapReferences for EncLogRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) -> Result<()> {
        Ok(())
    }
}

impl RemapReferences for EncMapRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) -> Result<()> {
        Ok(())
    }
}

impl RemapReferences for AssemblyRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) -> Result<()> {
        Ok(())
    }
}

impl RemapReferences for AssemblyProcessorRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) -> Result<()> {
        Ok(())
    }
}

impl RemapReferences for AssemblyOsRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) -> Result<()> {
        Ok(())
    }
}

impl RemapReferences for AssemblyRefProcessorRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // AssemblyRef: direct RID into AssemblyRef table
        self.assembly_ref = remapper.reference(
            Referrer::Column {
                row: self.token,
                column: "AssemblyRef",
            },
            TableId::AssemblyRef,
            self.assembly_ref,
        )?;
        Ok(())
    }
}

impl RemapReferences for AssemblyRefOsRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // AssemblyRef: direct RID into AssemblyRef table
        self.assembly_ref = remapper.reference(
            Referrer::Column {
                row: self.token,
                column: "AssemblyRef",
            },
            TableId::AssemblyRef,
            self.assembly_ref,
        )?;
        Ok(())
    }
}

impl RemapReferences for FileRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) -> Result<()> {
        Ok(())
    }
}

impl RemapReferences for DocumentRaw {
    // No column names a row: its heap columns are patched with the heaps
    fn remap_references(&mut self, _remapper: &RidRemapper) -> Result<()> {
        Ok(())
    }
}

impl RemapReferences for MethodDebugInformationRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // Document: direct RID into Document table
        self.document = remapper.reference(
            Referrer::Column {
                row: self.token,
                column: "Document",
            },
            TableId::Document,
            self.document,
        )?;
        Ok(())
    }
}

impl RemapReferences for LocalScopeRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // Method: direct RID into MethodDef table
        self.method = remapper.reference(
            Referrer::Column {
                row: self.token,
                column: "Method",
            },
            TableId::MethodDef,
            self.method,
        )?;
        // ImportScope: direct RID into ImportScope table
        self.import_scope = remapper.reference(
            Referrer::Column {
                row: self.token,
                column: "ImportScope",
            },
            TableId::ImportScope,
            self.import_scope,
        )?;
        // VariableList and ConstantList: list starts in LocalVariable and LocalConstant
        self.variable_list = remapper.list_start(TableId::LocalVariable, self.variable_list);
        self.constant_list = remapper.list_start(TableId::LocalConstant, self.constant_list);
        Ok(())
    }
}

impl RemapReferences for LocalVariableRaw {
    // No column names a row: its heap columns are patched with the heaps
    fn remap_references(&mut self, _remapper: &RidRemapper) -> Result<()> {
        Ok(())
    }
}

impl RemapReferences for LocalConstantRaw {
    // No column names a row: its heap columns are patched with the heaps
    fn remap_references(&mut self, _remapper: &RidRemapper) -> Result<()> {
        Ok(())
    }
}

impl RemapReferences for ImportScopeRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // Parent: direct RID into ImportScope table
        self.parent = remapper.reference(
            Referrer::Column {
                row: self.token,
                column: "Parent",
            },
            TableId::ImportScope,
            self.parent,
        )?;
        Ok(())
    }
}

impl RemapReferences for StateMachineMethodRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // MoveNextMethod and KickoffMethod: direct RIDs into MethodDef table
        self.move_next_method = remapper.reference(
            Referrer::Column {
                row: self.token,
                column: "MoveNextMethod",
            },
            TableId::MethodDef,
            self.move_next_method,
        )?;
        self.kickoff_method = remapper.reference(
            Referrer::Column {
                row: self.token,
                column: "KickoffMethod",
            },
            TableId::MethodDef,
            self.kickoff_method,
        )?;
        Ok(())
    }
}

impl RemapReferences for CustomDebugInformationRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        // Parent: HasCustomDebugInformation, any table it names (the PDB's own included)
        remapper.remap_coded_index(self.token, "Parent", &mut self.parent)?;
        Ok(())
    }
}

impl RemapReferences for TableDataOwned {
    fn remap_references(&mut self, remapper: &RidRemapper) -> Result<()> {
        match self {
            TableDataOwned::TypeRef(r) => r.remap_references(remapper),
            TableDataOwned::TypeDef(r) => r.remap_references(remapper),
            TableDataOwned::MethodDef(r) => r.remap_references(remapper),
            TableDataOwned::InterfaceImpl(r) => r.remap_references(remapper),
            TableDataOwned::MemberRef(r) => r.remap_references(remapper),
            TableDataOwned::Constant(r) => r.remap_references(remapper),
            TableDataOwned::CustomAttribute(r) => r.remap_references(remapper),
            TableDataOwned::FieldMarshal(r) => r.remap_references(remapper),
            TableDataOwned::DeclSecurity(r) => r.remap_references(remapper),
            TableDataOwned::ClassLayout(r) => r.remap_references(remapper),
            TableDataOwned::FieldLayout(r) => r.remap_references(remapper),
            TableDataOwned::EventMap(r) => r.remap_references(remapper),
            TableDataOwned::Event(r) => r.remap_references(remapper),
            TableDataOwned::PropertyMap(r) => r.remap_references(remapper),
            TableDataOwned::MethodSemantics(r) => r.remap_references(remapper),
            TableDataOwned::MethodImpl(r) => r.remap_references(remapper),
            TableDataOwned::ImplMap(r) => r.remap_references(remapper),
            TableDataOwned::FieldRVA(r) => r.remap_references(remapper),
            TableDataOwned::AssemblyRef(r) => r.remap_references(remapper),
            TableDataOwned::ExportedType(r) => r.remap_references(remapper),
            TableDataOwned::ManifestResource(r) => r.remap_references(remapper),
            TableDataOwned::NestedClass(r) => r.remap_references(remapper),
            TableDataOwned::GenericParam(r) => r.remap_references(remapper),
            TableDataOwned::MethodSpec(r) => r.remap_references(remapper),
            TableDataOwned::GenericParamConstraint(r) => r.remap_references(remapper),
            // Tables without cross-table references
            TableDataOwned::Module(_)
            | TableDataOwned::FieldPtr(_)
            | TableDataOwned::Field(_)
            | TableDataOwned::MethodPtr(_)
            | TableDataOwned::ParamPtr(_)
            | TableDataOwned::Param(_)
            | TableDataOwned::EventPtr(_)
            | TableDataOwned::Property(_)
            | TableDataOwned::PropertyPtr(_)
            | TableDataOwned::ModuleRef(_)
            | TableDataOwned::TypeSpec(_)
            | TableDataOwned::StandAloneSig(_)
            | TableDataOwned::EncLog(_)
            | TableDataOwned::EncMap(_)
            | TableDataOwned::Assembly(_)
            | TableDataOwned::AssemblyProcessor(_)
            | TableDataOwned::AssemblyOS(_)
            | TableDataOwned::AssemblyRefProcessor(_)
            | TableDataOwned::AssemblyRefOS(_)
            | TableDataOwned::File(_)
            | TableDataOwned::Document(_)
            | TableDataOwned::MethodDebugInformation(_)
            | TableDataOwned::LocalScope(_)
            | TableDataOwned::LocalVariable(_)
            | TableDataOwned::LocalConstant(_)
            | TableDataOwned::ImportScope(_)
            | TableDataOwned::StateMachineMethod(_)
            | TableDataOwned::CustomDebugInformation(_) => Ok(()),
        }
    }
}

impl RidRemapper {
    /// Check if a table needs remapping based on the tables it references.
    ///
    /// Returns true if any of the tables that `table_id` references have deletions.
    #[must_use]
    pub fn needs_remapping(&self, table_id: TableId) -> bool {
        if self.is_empty() {
            return false;
        }

        table_id
            .references()
            .iter()
            .any(|t| self.has_deletions(*t) || self.is_reordered(*t))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use strum::IntoEnumIterator;

    use super::*;
    use crate::{
        dispatch_table_type,
        metadata::tables::{CodedIndexType, TableInfo, TableRow},
    };

    /// A remapper for `table` of `count` rows with `deleted` rows deleted.
    fn deleting(
        table: TableId,
        deleted: &[u32],
        count: u32,
        dangling: DanglingPolicy,
    ) -> RidRemapper {
        let deleted: HashSet<u32> = deleted.iter().copied().collect();
        let (refs, list_starts) = RidRemapper::calculate_remapping(&deleted, count);
        RidRemapper {
            refs: [(table, refs)].into_iter().collect(),
            list_starts: [(table, list_starts)].into_iter().collect(),
            tables_with_deletions: [table].into_iter().collect(),
            deleted_rids: [(table, deleted)].into_iter().collect(),
            sort_orders: HashMap::new(),
            dangling,
        }
    }

    /// The referrer the tests name.
    const REFERRER: Referrer = Referrer::Column {
        row: Token::new(0x0C00_0001),
        column: "Type",
    };

    #[test]
    fn test_calculate_remapping_no_deletions() {
        let (refs, starts) = RidRemapper::calculate_remapping(&HashSet::new(), 10);
        assert!(refs.is_empty());
        assert!(starts.is_empty());
    }

    #[test]
    fn test_calculate_remapping_single_deletion() {
        let deleted = [3].into_iter().collect();
        let (refs, starts) = RidRemapper::calculate_remapping(&deleted, 10);

        // Row 3 deleted, rows 4-10 shift down by 1
        assert_eq!(refs.get(&1), None); // unchanged
        assert_eq!(refs.get(&2), None); // unchanged
        assert_eq!(refs.get(&3), None); // deleted: no new RID
        assert_eq!(refs.get(&4), Some(&3));
        assert_eq!(refs.get(&10), Some(&9));
        // A list starting at row 3 starts at what was row 4, now 3: unchanged.
        assert_eq!(starts.get(&3), None);
        // One past the end moves with the end.
        assert_eq!(starts.get(&11), Some(&10));
    }

    #[test]
    fn test_calculate_remapping_multiple_deletions() {
        let deleted = [3, 7].into_iter().collect();
        let (refs, starts) = RidRemapper::calculate_remapping(&deleted, 10);

        assert_eq!(refs.get(&1), None);
        assert_eq!(refs.get(&2), None);
        assert_eq!(refs.get(&4), Some(&3));
        assert_eq!(refs.get(&6), Some(&5));
        assert_eq!(refs.get(&8), Some(&6));
        assert_eq!(refs.get(&10), Some(&8));
        assert!(!refs.contains_key(&3) && !refs.contains_key(&7));
        assert_eq!(starts.get(&7), Some(&6));
    }

    #[test]
    fn test_calculate_remapping_consecutive_deletions() {
        let deleted = [3, 4, 5].into_iter().collect();
        let (refs, starts) = RidRemapper::calculate_remapping(&deleted, 10);

        assert_eq!(refs.get(&6), Some(&3));
        assert_eq!(refs.get(&10), Some(&7));
        // Each deleted row continues at what was row 6.
        assert_eq!(starts.get(&4), Some(&3));
        assert_eq!(starts.get(&5), Some(&3));
    }

    #[test]
    fn test_calculate_remapping_first_row_deleted() {
        let deleted = [1].into_iter().collect();
        let (refs, _) = RidRemapper::calculate_remapping(&deleted, 5);

        assert_eq!(refs.get(&2), Some(&1));
        assert_eq!(refs.get(&5), Some(&4));
    }

    #[test]
    fn test_calculate_remapping_last_row_deleted() {
        let deleted = [10].into_iter().collect();
        let (refs, starts) = RidRemapper::calculate_remapping(&deleted, 10);

        // Surviving rows 1-9 keep their RIDs.
        assert!(refs.is_empty());
        // The deleted last row and one past the end both continue at the new end.
        assert_eq!(starts.len(), 1);
        assert_eq!(starts.get(&11), Some(&10));
    }

    #[test]
    fn a_reference_follows_the_shift() {
        let remapper = deleting(TableId::MethodDef, &[3], 10, DanglingPolicy::Error);

        assert_eq!(
            remapper.reference(REFERRER, TableId::MethodDef, 0).unwrap(),
            0
        );
        assert_eq!(
            remapper.reference(REFERRER, TableId::MethodDef, 2).unwrap(),
            2
        );
        assert_eq!(
            remapper.reference(REFERRER, TableId::MethodDef, 4).unwrap(),
            3
        );
        assert_eq!(remapper.reference(REFERRER, TableId::Field, 5).unwrap(), 5);
    }

    #[test]
    fn a_reference_to_a_deleted_row_is_dangling_never_retargeted() {
        let remapper = deleting(TableId::MethodDef, &[3], 10, DanglingPolicy::Error);

        let err = remapper
            .reference(REFERRER, TableId::MethodDef, 3)
            .unwrap_err();
        assert!(
            matches!(
                err,
                Error::DanglingReference { referrer, target }
                    if referrer == REFERRER && target == Token::new(0x0600_0003)
            ),
            "{err}"
        );
    }

    #[test]
    fn a_dangling_reference_is_null_under_the_null_policy() {
        let remapper = deleting(TableId::MethodDef, &[3], 10, DanglingPolicy::Null);

        assert_eq!(
            remapper.reference(REFERRER, TableId::MethodDef, 3).unwrap(),
            0
        );
    }

    #[test]
    fn a_list_starting_at_a_deleted_row_continues_at_the_next_survivor() {
        let remapper = deleting(TableId::MethodDef, &[3, 4], 10, DanglingPolicy::Error);

        assert_eq!(remapper.list_start(TableId::MethodDef, 3), 3);
        assert_eq!(remapper.list_start(TableId::MethodDef, 4), 3);
        assert_eq!(remapper.list_start(TableId::MethodDef, 6), 4);
        assert_eq!(remapper.list_start(TableId::MethodDef, 11), 9);
    }

    #[test]
    fn test_remap_coded_index() {
        let remapper = deleting(TableId::MethodDef, &[3], 10, DanglingPolicy::Error);
        let row = Token::new(0x0C00_0001);

        let mut ci = CodedIndex::new(TableId::MethodDef, 5, CodedIndexType::HasCustomAttribute);
        remapper.remap_coded_index(row, "Parent", &mut ci).unwrap();
        assert_eq!(ci.row, 4);
        assert_eq!(ci.token.row(), 4);

        let mut ci2 = CodedIndex::new(TableId::TypeDef, 5, CodedIndexType::HasCustomAttribute);
        remapper.remap_coded_index(row, "Parent", &mut ci2).unwrap();
        assert_eq!(ci2.row, 5);

        let mut deleted =
            CodedIndex::new(TableId::MethodDef, 3, CodedIndexType::HasCustomAttribute);
        let err = remapper
            .remap_coded_index(row, "Parent", &mut deleted)
            .unwrap_err();
        assert!(
            matches!(
                err,
                Error::DanglingReference {
                    referrer: Referrer::Column { row: r, column: "Parent" },
                    target,
                } if r == row && target == Token::new(0x0600_0003)
            ),
            "{err}"
        );
    }

    #[test]
    fn test_remap_coded_index_null() {
        let remapper = RidRemapper::empty();

        let mut ci = CodedIndex::new(TableId::MethodDef, 0, CodedIndexType::HasCustomAttribute);
        remapper
            .remap_coded_index(Token::new(0x0C00_0001), "Parent", &mut ci)
            .unwrap();
        assert_eq!(ci.row, 0);
    }

    #[test]
    fn test_typedef_remap_references() {
        let remapper = deleting(TableId::MethodDef, &[3], 10, DanglingPolicy::Error);

        let mut typedef = TypeDefRaw {
            rid: 1,
            token: Token::new(0x02000001),
            offset: 0,
            flags: 0,
            type_name: 0,
            type_namespace: 0,
            extends: CodedIndex::null(CodedIndexType::TypeDefOrRef),
            field_list: 1,
            method_list: 3, // starts at the deleted MethodDef row 3
        };

        typedef.remap_references(&remapper).unwrap();

        // A list column is not a reference: it continues at the next survivor.
        assert_eq!(typedef.method_list, 3);
    }

    #[test]
    fn surviving_remap_holds_no_deleted_row() {
        let remapper = deleting(TableId::TypeDef, &[3], 5, DanglingPolicy::Error);

        let sig_remap = remapper
            .surviving_remap(TableId::TypeDef)
            .expect("should have remap");
        assert!(!sig_remap.contains_key(&3));
        assert_eq!(sig_remap.get(&4), Some(&3));
        assert_eq!(sig_remap.get(&5), Some(&4));
        assert!(remapper.surviving_remap(TableId::MethodDef).is_none());
    }

    #[test]
    fn a_token_naming_a_deleted_row_is_dangling() {
        let mut tokens =
            deleting(TableId::MethodDef, &[3], 10, DanglingPolicy::Error).token_remap();
        let body = Referrer::Body(Token::new(0x0600_0001));

        assert_eq!(tokens.remap(body, 0x0600_0004).unwrap(), 0x0600_0003);
        assert_eq!(tokens.remap(body, 0x0400_0004).unwrap(), 0x0400_0004);
        let err = tokens.remap(body, 0x0600_0003).unwrap_err();
        assert!(
            matches!(err, Error::DanglingReference { referrer, target }
                if referrer == body && target == Token::new(0x0600_0003)),
            "{err}"
        );

        // A token the write renumbers itself, as the StandAloneSig deduplication does.
        tokens.insert(0x1100_0002, 0x1100_0001);
        assert_eq!(tokens.remap(body, 0x1100_0002).unwrap(), 0x1100_0001);

        let null = deleting(TableId::MethodDef, &[3], 10, DanglingPolicy::Null).token_remap();
        assert_eq!(null.remap(body, 0x0600_0003).unwrap(), 0x0600_0000);
    }

    /// A remapper deleting `deleted` rows of each table of `count` rows.
    fn deleting_in(tables: &[(TableId, &[u32], u32)]) -> RidRemapper {
        let mut remapper = RidRemapper::empty();
        for &(table, deleted, count) in tables {
            let deleted: HashSet<u32> = deleted.iter().copied().collect();
            let (refs, list_starts) = RidRemapper::calculate_remapping(&deleted, count);
            remapper.refs.insert(table, refs);
            remapper.list_starts.insert(table, list_starts);
            remapper.tables_with_deletions.insert(table);
            remapper.deleted_rids.insert(table, deleted);
        }
        remapper
    }

    /// The Portable PDB tables' row columns follow the rows they name: a method's document,
    /// a scope's method, import scope and lists, an import scope's parent, a state machine's
    /// methods and a custom debug information row's parent; and a deleted document is a
    /// dangling reference.
    #[test]
    fn debug_table_columns_follow_their_rows() {
        let remapper = deleting_in(&[
            (TableId::Document, &[1], 5),
            (TableId::MethodDef, &[1], 6),
            (TableId::ImportScope, &[1], 4),
            (TableId::LocalVariable, &[1], 4),
            (TableId::LocalConstant, &[1], 4),
        ]);

        let mut info = MethodDebugInformationRaw {
            rid: 1,
            token: Token::new(0x3100_0001),
            offset: 0,
            document: 3,
            sequence_points: 0,
        };
        info.remap_references(&remapper).unwrap();
        assert_eq!(info.document, 2);

        let mut scope = LocalScopeRaw {
            rid: 1,
            token: Token::new(0x3200_0001),
            offset: 0,
            method: 4,
            import_scope: 3,
            variable_list: 3,
            constant_list: 2,
            start_offset: 0,
            length: 8,
        };
        scope.remap_references(&remapper).unwrap();
        assert_eq!(
            (
                scope.method,
                scope.import_scope,
                scope.variable_list,
                scope.constant_list
            ),
            (3, 2, 2, 1)
        );

        let mut import_scope = ImportScopeRaw {
            rid: 3,
            token: Token::new(0x3500_0003),
            offset: 0,
            parent: 2,
            imports: 0,
        };
        import_scope.remap_references(&remapper).unwrap();
        assert_eq!(import_scope.parent, 1);

        let mut state_machine = StateMachineMethodRaw {
            rid: 1,
            token: Token::new(0x3600_0001),
            offset: 0,
            move_next_method: 5,
            kickoff_method: 4,
        };
        state_machine.remap_references(&remapper).unwrap();
        assert_eq!(
            (state_machine.move_next_method, state_machine.kickoff_method),
            (4, 3)
        );

        let mut record = CustomDebugInformationRaw {
            rid: 1,
            token: Token::new(0x3700_0001),
            offset: 0,
            parent: CodedIndex::new(
                TableId::Document,
                3,
                CodedIndexType::HasCustomDebugInformation,
            ),
            kind: 1,
            value: 0,
        };
        record.remap_references(&remapper).unwrap();
        assert_eq!(record.parent.row, 2);

        let mut deleted = MethodDebugInformationRaw {
            document: 1,
            ..info
        };
        assert!(matches!(
            deleted.remap_references(&remapper),
            Err(Error::DanglingReference { target, .. }) if target == Token::new(0x3000_0001)
        ));
    }

    /// The pointer tables and the AssemblyRef processor and OS tables follow the rows they
    /// name.
    #[test]
    fn pointer_and_assembly_ref_columns_follow_their_rows() {
        let remapper = deleting_in(&[(TableId::Field, &[1], 5), (TableId::AssemblyRef, &[1], 3)]);
        let mut pointer = FieldPtrRaw {
            rid: 1,
            token: Token::new(0x0300_0001),
            offset: 0,
            field: 3,
        };
        pointer.remap_references(&remapper).unwrap();
        assert_eq!(pointer.field, 2);

        let mut os = AssemblyRefOsRaw {
            rid: 1,
            token: Token::new(0x2500_0001),
            offset: 0,
            os_platform_id: 2,
            os_major_version: 6,
            os_minor_version: 1,
            assembly_ref: 2,
        };
        os.remap_references(&remapper).unwrap();
        assert_eq!(os.assembly_ref, 1);
    }

    /// `TableId::references` names every table a row's columns can name, as the row layouts
    /// say: a column naming a table, directly or through a coded index, widens to four bytes
    /// when that table outgrows two-byte indexes, so a row is larger against a layout where
    /// only that table is large. The writer renumbers a table's rows only when a table its
    /// `references` names loses rows, so a table missing there keeps stale rows.
    #[test]
    fn references_name_every_table_a_row_names() {
        let size = |table: TableId, large: Option<TableId>| -> u32 {
            let rows: Vec<(TableId, u32)> = large
                .into_iter()
                .map(|large| (large, 0x0001_0000))
                .collect();
            let info = Arc::new(TableInfo::new_test(&rows, false, false, false));
            dispatch_table_type!(table, |RawType| RawType::row_size(&info))
        };
        for table in TableId::iter() {
            let base = size(table, None);
            let named: HashSet<TableId> = TableId::iter()
                .filter(|&target| size(table, Some(target)) > base)
                .collect();
            let listed: HashSet<TableId> = table.references().iter().copied().collect();
            assert_eq!(listed, named, "{table:?}");
            assert_eq!(table.has_cross_references(), !named.is_empty(), "{table:?}");
        }
    }
}

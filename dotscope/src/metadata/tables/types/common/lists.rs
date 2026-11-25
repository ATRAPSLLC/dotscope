//! Normalized runs of the ECMA-335 list columns.
//!
//! Several metadata tables own a contiguous run of rows in another table through a single
//! "list" column (ECMA-335 II.22): the column names the first member of the owner's run, and
//! the run continues up to (but not including) the member the next owner's column names, or to
//! the end of the member table for the last owner. The columns encoded this way are:
//!
//! | Owner column                   | Members         | Indirection (`#-` streams) |
//! |--------------------------------|-----------------|----------------------------|
//! | `TypeDef.FieldList`            | `Field`         | `FieldPtr`                 |
//! | `TypeDef.MethodList`           | `MethodDef`     | `MethodPtr`                |
//! | `MethodDef.ParamList`          | `Param`         | `ParamPtr`                 |
//! | `EventMap.EventList`           | `Event`         | `EventPtr`                 |
//! | `PropertyMap.PropertyList`     | `Property`      | `PropertyPtr`              |
//! | `LocalScope.VariableList`      | `LocalVariable` | none (Portable PDB)        |
//! | `LocalScope.ConstantList`      | `LocalConstant` | none (Portable PDB)        |
//!
//! When the indirection table has rows, the list columns index *positions* in it rather than
//! member rows directly, and each position names the member row through the Ptr table's single
//! column. The run arithmetic is the same either way; only the bound differs (the Ptr table's
//! row count instead of the member table's).
//!
//! # Why the runs are normalized
//!
//! The columns are attacker-controlled. Read literally, a column past the member table makes a
//! run of up to 2^32 members (four-byte indexes), and columns that go down and up again make
//! runs that overlap: T owners alternating between 1 and the last member each own nearly every
//! member, so eagerly resolving them costs T x F instead of F. [`MemberRanges`] reads every
//! owner's column once and fixes them up in one pass, so that the runs it hands out are
//! disjoint, lie inside the member table and together cost O(owners + members):
//!
//! - a column of 0, or an owner row that cannot be read, marks an *absent* run: that owner owns
//!   nothing, and the previous owner's run ends where it would have started (both empty, as
//!   `System.Reflection.Metadata` reads such rows);
//! - a column past `member_rows + 1` is clamped to `member_rows + 1` (the run ends with the
//!   table);
//! - a column below the previous owner's start is raised to it (that owner's run is empty and
//!   the previous one ends where the next well-ordered start lies).
//!
//! Every owner whose column was changed by the last two rules is recorded in
//! [`MemberRanges::adjusted`], and every absent owner in [`MemberRanges::absent`], so a loader
//! can report what it fixed up. Well-formed metadata (every compiler's output) passes through
//! unchanged and records nothing.
//!
//! # Reference
//!
//! * [ECMA-335 Partition II, Section 22](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Metadata logical format: tables
//! * [Portable PDB format, LocalScope table](https://github.com/dotnet/runtime/blob/main/docs/design/specs/PortablePdb-Metadata.md#localscope-table-0x32)

use std::ops::Range;

use crossbeam_skiplist::SkipMap;

use crate::{
    metadata::{tables::TableId, token::Token},
    Result,
};

/// One of the ECMA-335 list columns that own a run of rows in another table.
///
/// Each variant names the owner table, the member table and, for the type-system lists, the
/// Ptr table that `#-` (uncompressed) streams may interpose between them. See the module
/// documentation for the table of columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemberList {
    /// `TypeDef.FieldList`: the fields a type defines.
    TypeDefFields,
    /// `TypeDef.MethodList`: the methods a type defines.
    TypeDefMethods,
    /// `MethodDef.ParamList`: the parameter rows of a method.
    MethodDefParams,
    /// `EventMap.EventList`: the events of the mapped type.
    EventMapEvents,
    /// `PropertyMap.PropertyList`: the properties of the mapped type.
    PropertyMapProperties,
    /// `LocalScope.VariableList`: the local variables a Portable PDB scope declares.
    LocalScopeVariables,
    /// `LocalScope.ConstantList`: the local constants a Portable PDB scope declares.
    LocalScopeConstants,
}

impl MemberList {
    /// The table whose rows carry the list column.
    #[must_use]
    pub const fn owner_table(self) -> TableId {
        match self {
            MemberList::TypeDefFields | MemberList::TypeDefMethods => TableId::TypeDef,
            MemberList::MethodDefParams => TableId::MethodDef,
            MemberList::EventMapEvents => TableId::EventMap,
            MemberList::PropertyMapProperties => TableId::PropertyMap,
            MemberList::LocalScopeVariables | MemberList::LocalScopeConstants => {
                TableId::LocalScope
            }
        }
    }

    /// The table the runs select rows of.
    #[must_use]
    pub const fn member_table(self) -> TableId {
        match self {
            MemberList::TypeDefFields => TableId::Field,
            MemberList::TypeDefMethods => TableId::MethodDef,
            MemberList::MethodDefParams => TableId::Param,
            MemberList::EventMapEvents => TableId::Event,
            MemberList::PropertyMapProperties => TableId::Property,
            MemberList::LocalScopeVariables => TableId::LocalVariable,
            MemberList::LocalScopeConstants => TableId::LocalConstant,
        }
    }

    /// The indirection table `#-` streams may place between the column and the members, if
    /// the list has one (the Portable PDB lists do not).
    #[must_use]
    pub const fn ptr_table(self) -> Option<TableId> {
        match self {
            MemberList::TypeDefFields => Some(TableId::FieldPtr),
            MemberList::TypeDefMethods => Some(TableId::MethodPtr),
            MemberList::MethodDefParams => Some(TableId::ParamPtr),
            MemberList::EventMapEvents => Some(TableId::EventPtr),
            MemberList::PropertyMapProperties => Some(TableId::PropertyPtr),
            MemberList::LocalScopeVariables | MemberList::LocalScopeConstants => None,
        }
    }
}

/// The normalized runs of one list column: which positions each owner row owns.
///
/// Built once per owner table in O(owner rows) from the raw column values (see the module
/// documentation for the normalization rules), after which [`range`](Self::range) and
/// [`owner_of`](Self::owner_of) answer in O(1) and O(log owners). The runs are disjoint, lie in
/// `1..=member_rows` and are in owner order, whatever the input.
///
/// Positions are member rows when [`is_indirect`](Self::is_indirect) is false, and positions in
/// the Ptr table (1-based, each naming a member row) when it is true.
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::tables::{MemberList, MemberRanges};
///
/// // Three owners over four members: the first owns members 1 and 2, the second none, the
/// // third 3 and 4 (the last run ends with the member table).
/// let columns = [1, 3, 3];
/// let ranges = MemberRanges::new(MemberList::TypeDefFields, 3, 4, false, |rid| {
///     columns.get(rid as usize - 1).copied()
/// });
/// assert_eq!(ranges.range(1), 1..3);
/// assert_eq!(ranges.range(2), 3..3);
/// assert_eq!(ranges.range(3), 3..5);
/// assert_eq!(ranges.owner_of(4), Some(3));
///
/// // Columns that go down again would overlap: they are raised to the previous start.
/// let hostile = [1, 0xFFFF_FFFF, 1];
/// let ranges = MemberRanges::new(MemberList::TypeDefFields, 3, 4, false, |rid| {
///     hostile.get(rid as usize - 1).copied()
/// });
/// assert_eq!(ranges.range(1), 1..5);
/// assert!(ranges.range(2).is_empty());
/// assert!(ranges.range(3).is_empty());
/// assert_eq!(ranges.adjusted(), &[2, 3]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberRanges {
    /// The list column these runs were read from.
    list: MemberList,
    /// `starts[i]` is the first position of owner rid `i + 1`; `starts[owner_rows]` is
    /// `member_rows + 1`. Non-decreasing and inside `1..=member_rows + 1`.
    starts: Box<[u32]>,
    /// Owner rids, ascending, whose column was 0 or whose row could not be read.
    absent: Box<[u32]>,
    /// Owner rids, ascending, whose column was past the member table or below the previous
    /// owner's start.
    adjusted: Box<[u32]>,
    /// The number of positions the runs cover.
    member_rows: u32,
    /// Whether positions are Ptr-table positions rather than member rows.
    indirect: bool,
}

impl MemberRanges {
    /// Normalizes the list column of `owner_rows` owners over `member_rows` positions.
    ///
    /// `list_start(rid)` returns owner `rid`'s raw column value (`1..=owner_rows`), or `None`
    /// when that row cannot be read. It is called once per owner, in rid order. `indirect`
    /// records whether the positions go through a Ptr table; it does not change the arithmetic,
    /// and `member_rows` must then be the Ptr table's row count. It is ignored for a list
    /// without a Ptr table ([`MemberList::ptr_table`] is `None`).
    #[must_use]
    pub fn new(
        list: MemberList,
        owner_rows: u32,
        member_rows: u32,
        indirect: bool,
        mut list_start: impl FnMut(u32) -> Option<u32>,
    ) -> Self {
        let end = member_rows.saturating_add(1);
        let mut starts = Vec::with_capacity((owner_rows as usize).saturating_add(1));
        let mut absent = Vec::new();
        let mut adjusted = Vec::new();
        let mut previous = 1u32;

        for rid in 1..=owner_rows {
            let start = match list_start(rid) {
                None | Some(0) => {
                    absent.push(rid);
                    previous
                }
                Some(raw) => {
                    let start = raw.min(end).max(previous);
                    if start != raw {
                        adjusted.push(rid);
                    }
                    start
                }
            };
            starts.push(start);
            previous = start;
        }
        starts.push(end);

        MemberRanges {
            list,
            starts: starts.into_boxed_slice(),
            absent: absent.into_boxed_slice(),
            adjusted: adjusted.into_boxed_slice(),
            member_rows,
            indirect: indirect && list.ptr_table().is_some(),
        }
    }

    /// Ranges for `list` when its owner table is absent: every lookup is empty.
    #[must_use]
    pub fn empty(list: MemberList) -> Self {
        Self::new(list, 0, 0, false, |_| None)
    }

    /// The list column these runs were read from.
    #[must_use]
    pub fn list(&self) -> MemberList {
        self.list
    }

    /// The number of owner rows the column was read from.
    #[must_use]
    pub fn owner_rows(&self) -> u32 {
        // `starts` holds one entry per owner plus the end sentinel, and was built from a u32
        // owner count, so the length minus one fits.
        u32::try_from(self.starts.len().saturating_sub(1)).unwrap_or(u32::MAX)
    }

    /// The number of positions the runs cover (`member_rows` as given to [`new`](Self::new)).
    #[must_use]
    pub fn member_rows(&self) -> u32 {
        self.member_rows
    }

    /// Whether the positions index a Ptr table (each position naming a member row through it)
    /// rather than the member table itself.
    #[must_use]
    pub fn is_indirect(&self) -> bool {
        self.indirect
    }

    /// The positions owner `owner_rid` owns, `start..end` with `1 <= start <= end` and `end`
    /// at most one past [`member_rows`](Self::member_rows) (saturating at `u32::MAX`, a count no
    /// metadata table can reach: rids are 24-bit).
    ///
    /// Empty for an absent owner, for rid 0 and for rids past the owner table.
    #[must_use]
    pub fn range(&self, owner_rid: u32) -> Range<u32> {
        let Some(index) = (owner_rid as usize).checked_sub(1) else {
            return 0..0;
        };
        match (
            self.starts.get(index),
            self.starts.get(index.saturating_add(1)),
        ) {
            (Some(&start), Some(&end)) if self.absent.binary_search(&owner_rid).is_err() => {
                start..end
            }
            _ => 0..0,
        }
    }

    /// The owner whose run contains `position`, or `None` when no owner owns it (position 0,
    /// past the members, before the first owner's run, or inside the gap an absent owner
    /// leaves).
    #[must_use]
    pub fn owner_of(&self, position: u32) -> Option<u32> {
        if position == 0 || position > self.member_rows() {
            return None;
        }
        let owners = self
            .starts
            .split_last()
            .map_or(&[][..], |(_, owners)| owners);
        // The owner containing `position` is the last one starting at or before it: owners
        // sharing that start before it have empty runs.
        let index = owners
            .partition_point(|&start| start <= position)
            .checked_sub(1)?;
        let rid = u32::try_from(index).ok()?.checked_add(1)?;
        self.range(rid).contains(&position).then_some(rid)
    }

    /// The members owner `owner_rid` owns, in run order, looked up in the loaded maps.
    ///
    /// Each position of the owner's [`range`](Self::range) names a member row directly, or, when
    /// the runs are [indirect](Self::is_indirect), a row of `ptr` (keyed by the list's Ptr-table
    /// tokens) whose `ptr_target` is the member row. The member is then looked up in `members`
    /// (keyed by member-table tokens).
    ///
    /// # Errors
    ///
    /// Yields an error for a position whose Ptr row or member row is not in its map: the row
    /// failed to load, or a Ptr entry names a member row that does not exist.
    pub fn members<'m, P, M>(
        &'m self,
        owner_rid: u32,
        ptr: &'m SkipMap<Token, P>,
        ptr_target: impl Fn(&P) -> u32 + 'm,
        members: &'m SkipMap<Token, M>,
    ) -> impl Iterator<Item = Result<M>> + 'm
    where
        P: Send + 'static,
        M: Clone + Send + 'static,
    {
        self.range(owner_rid).map(move |position| {
            let rid = match self.list.ptr_table() {
                Some(ptr_table) if self.indirect => {
                    let token = Token::from_parts(ptr_table, position);
                    let entry = ptr.get(&token).ok_or_else(|| {
                        malformed_error!(
                            "{:?} row {} of {:?} {} is not loaded",
                            ptr_table,
                            position,
                            self.list.owner_table(),
                            owner_rid
                        )
                    })?;
                    ptr_target(entry.value())
                }
                _ => position,
            };
            self.member(owner_rid, rid, members)
        })
    }

    /// The members owner `owner_rid` owns, for a list without a Ptr table (the Portable PDB
    /// `LocalScope` lists): each position of the owner's [`range`](Self::range) is a member row,
    /// looked up in `members` (keyed by member-table tokens).
    ///
    /// For a list that has a Ptr table use [`members`](Self::members), which follows the Ptr
    /// table when the runs are indirect; this method takes positions as member rows.
    ///
    /// # Errors
    ///
    /// Yields an error for a position whose member row is not in `members` (it failed to load).
    pub fn direct_members<'m, M: Clone + Send + 'static>(
        &'m self,
        owner_rid: u32,
        members: &'m SkipMap<Token, M>,
    ) -> impl Iterator<Item = Result<M>> + 'm {
        self.range(owner_rid)
            .map(move |rid| self.member(owner_rid, rid, members))
    }

    /// Looks up member row `rid` of owner `owner_rid` in `members`.
    fn member<M: Clone + Send + 'static>(
        &self,
        owner_rid: u32,
        rid: u32,
        members: &SkipMap<Token, M>,
    ) -> Result<M> {
        let member_table = self.list.member_table();
        members
            .get(&Token::from_parts(member_table, rid))
            .map(|entry| entry.value().clone())
            .ok_or_else(|| {
                malformed_error!(
                    "{:?} row {} of {:?} {} is not loaded",
                    member_table,
                    rid,
                    self.list.owner_table(),
                    owner_rid
                )
            })
    }

    /// Owner rids, ascending, whose column was 0 or whose row could not be read. They own
    /// nothing.
    #[must_use]
    pub fn absent(&self) -> &[u32] {
        &self.absent
    }

    /// Owner rids, ascending, whose column lay past the member table or below the previous
    /// owner's start and was moved into place.
    #[must_use]
    pub fn adjusted(&self) -> &[u32] {
        &self.adjusted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(columns: &[u32], members: u32) -> MemberRanges {
        let owners = u32::try_from(columns.len()).unwrap();
        MemberRanges::new(MemberList::TypeDefFields, owners, members, false, |rid| {
            columns.get(rid as usize - 1).copied()
        })
    }

    /// Positions each owner gets, as a list per owner rid.
    fn runs(ranges: &MemberRanges) -> Vec<Range<u32>> {
        (1..=ranges.owner_rows())
            .map(|rid| ranges.range(rid))
            .collect()
    }

    #[test]
    fn well_formed_columns_pass_through() {
        let ranges = build(&[1, 3, 3, 6], 7);
        assert_eq!(runs(&ranges), vec![1..3, 3..3, 3..6, 6..8]);
        assert!(ranges.adjusted().is_empty());
        assert!(ranges.absent().is_empty());
        assert_eq!(ranges.member_rows(), 7);
        assert_eq!(ranges.owner_rows(), 4);
    }

    #[test]
    fn last_owner_runs_to_the_end_of_the_members() {
        assert_eq!(runs(&build(&[1], 5)), vec![1..6]);
        // One past the end is the legal "owns nothing" value for the last owner.
        let ranges = build(&[1, 6], 5);
        assert_eq!(runs(&ranges), vec![1..6, 6..6]);
        assert!(ranges.adjusted().is_empty());
    }

    #[test]
    fn no_members_gives_empty_runs() {
        let ranges = build(&[1, 1, 1], 0);
        assert_eq!(runs(&ranges), vec![1..1, 1..1, 1..1]);
        assert!(ranges.adjusted().is_empty());
    }

    #[test]
    fn columns_past_the_member_table_are_clamped() {
        // The hostile LocalScope case: a four-byte column of 0xFFFFFFFF.
        let ranges = build(&[1, 0xFFFF_FFFF], 3);
        assert_eq!(runs(&ranges), vec![1..4, 4..4]);
        assert_eq!(ranges.adjusted(), &[2]);
        assert_eq!(build(&[0xFFFF_FFFF], 3).range(1), 4..4);
    }

    #[test]
    fn decreasing_columns_cannot_overlap() {
        // Alternating starts would let every other owner own nearly every member.
        let columns: Vec<u32> = (0..100).map(|i| if i % 2 == 0 { 1 } else { 50 }).collect();
        let ranges = build(&columns, 100);
        let total: u32 = runs(&ranges).iter().map(|r| r.end - r.start).sum();
        assert_eq!(total, 100, "the runs partition the members exactly once");
        for pair in runs(&ranges).windows(2) {
            assert!(pair[0].end <= pair[1].start || pair[1].is_empty());
        }
        assert_eq!(ranges.range(1), 1..50);
        assert_eq!(ranges.range(2), 50..50);
    }

    #[test]
    fn zero_and_unreadable_owners_are_absent() {
        // Owner 2 reads 0, owner 3 cannot be read: both own nothing, and owner 1's run ends
        // where they would have started (empty), as System.Reflection.Metadata reads them.
        let columns = [3, 0, 99, 5];
        let ranges = MemberRanges::new(MemberList::TypeDefFields, 4, 6, false, |rid| match rid {
            3 => None,
            rid => columns.get(rid as usize - 1).copied(),
        });
        assert_eq!(runs(&ranges), vec![3..3, 0..0, 0..0, 5..7]);
        assert_eq!(ranges.absent(), &[2, 3]);
        assert!(ranges.adjusted().is_empty());
        // Members 3 and 4 are owned by nobody.
        assert_eq!(ranges.owner_of(3), None);
        assert_eq!(ranges.owner_of(4), None);
        assert_eq!(ranges.owner_of(5), Some(4));
    }

    #[test]
    fn leading_zero_columns_start_at_one() {
        let ranges = build(&[0, 2], 3);
        assert_eq!(runs(&ranges), vec![0..0, 2..4]);
        assert_eq!(ranges.owner_of(1), None);
    }

    #[test]
    fn owner_of_inverts_range() {
        let ranges = build(&[1, 4, 4, 4, 9, 9], 10);
        for rid in 1..=ranges.owner_rows() {
            for position in ranges.range(rid) {
                assert_eq!(ranges.owner_of(position), Some(rid), "position {position}");
            }
        }
        assert_eq!(ranges.owner_of(0), None);
        assert_eq!(ranges.owner_of(11), None);
        // A first run that does not start at 1 leaves the leading members ownerless.
        assert_eq!(build(&[3], 5).owner_of(2), None);
    }

    #[test]
    fn rids_outside_the_owner_table_are_empty() {
        let ranges = build(&[1, 2], 3);
        assert!(ranges.range(0).is_empty());
        assert!(ranges.range(3).is_empty());
        assert!(ranges.range(u32::MAX).is_empty());
        let empty = MemberRanges::empty(MemberList::EventMapEvents);
        assert!(empty.range(1).is_empty());
        assert_eq!(empty.owner_of(1), None);
        assert_eq!(empty.list(), MemberList::EventMapEvents);
    }

    #[test]
    fn extreme_counts_do_not_overflow() {
        let ranges = MemberRanges::new(MemberList::MethodDefParams, 2, u32::MAX, true, Some);
        assert!(ranges.is_indirect());
        assert_eq!(ranges.range(1), 1..2);
        assert_eq!(ranges.range(2), 2..u32::MAX);
        assert_eq!(ranges.member_rows(), u32::MAX);
    }

    #[test]
    fn member_list_tables() {
        assert_eq!(MemberList::TypeDefFields.owner_table(), TableId::TypeDef);
        assert_eq!(MemberList::TypeDefFields.member_table(), TableId::Field);
        assert_eq!(
            MemberList::MethodDefParams.ptr_table(),
            Some(TableId::ParamPtr)
        );
        assert_eq!(MemberList::LocalScopeConstants.ptr_table(), None);
        assert_eq!(
            MemberList::LocalScopeVariables.member_table(),
            TableId::LocalVariable
        );
    }
}

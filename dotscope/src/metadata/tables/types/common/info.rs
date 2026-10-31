//! Table metadata and size information for .NET metadata tables.
//!
//! This module provides utilities for tracking metadata table properties such as row counts,
//! index sizes, and coded index calculations. These structures are essential for properly
//! parsing .NET assemblies where table and heap sizes determine the byte width of various
//! reference fields.
//!
//! ## Key Components
//!
//! - [`crate::metadata::tables::types::TableRowInfo`] - Information about individual table sizes and indexing requirements
//! - [`crate::metadata::tables::types::TableInfo`] - Comprehensive metadata for all tables in an assembly
//! - [`crate::metadata::tables::types::TableInfoRef`] - Shared reference to table information
//!
//! ## Index Size Determination
//!
//! The .NET metadata format uses variable-width indices to optimize space usage:
//!
//! - **Table Indices**: 2 bytes if table has ≤65535 rows, 4 bytes otherwise
//! - **Heap Indices**: Size determined by heap size flags in metadata header
//! - **Coded Indices**: Size calculated based on maximum table size in the coded index union
//!
//! ## Reference
//!
//! * [ECMA-335 Partition II, Section 22.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Metadata Tables
//! * [ECMA-335 Partition II, Section 24.2.6](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Coded Indices

use std::sync::Arc;

use strum::{EnumCount, IntoEnumIterator};

use crate::{
    metadata::tables::types::{CodedIndexType, TableId},
    utils::{read_le, read_le_at},
    Result,
};

/// Information about the size and indexing properties of a metadata table.
///
/// This structure tracks essential properties of individual metadata tables that determine
/// how references to table entries are encoded in the assembly binary format.
///
/// ## Fields
///
/// - **`rows`**: Total number of entries in this table
/// - **`bits`**: Minimum bits required to represent any valid row index
/// - **`is_large`**: Whether this table requires 4-byte indices (>65535 rows)
///
/// ## Index Size Calculation
///
/// Tables with more than 65535 rows require 4-byte indices instead of the standard 2-byte
/// indices. This affects the binary layout of any structure that references this table.
#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub struct TableRowInfo {
    /// The total number of rows/entries in this table.
    ///
    /// This count determines whether the table requires 2-byte or 4-byte indices
    /// when referenced from other metadata structures.
    pub rows: u32,

    /// The minimum number of bits required to represent any valid row index.
    ///
    /// Calculated as `ceil(log2(rows))`, this value determines the minimum
    /// bit width needed for efficient storage of table indices.
    pub bits: u8,

    /// Whether this table requires large (4-byte) indices due to size.
    ///
    /// Set to `true` when `rows > 65535`, indicating that references to this
    /// table must use 4-byte indices instead of the standard 2-byte indices.
    pub is_large: bool,
}

impl TableRowInfo {
    /// Creates a new `TableRowInfo` instance with the given row count.
    ///
    /// Automatically calculates the number of bits required to represent
    /// indices into a table with the specified number of rows, and determines
    /// whether large (4-byte) indices are required.
    ///
    /// ## Algorithm
    ///
    /// - **Bit calculation**: `ceil(log2(rows))` or 1 for empty tables
    /// - **Large table detection**: `rows > 65535` requires 4-byte indices
    ///
    /// ## Arguments
    ///
    /// * `rows` - The number of rows in the table
    ///
    /// ## Returns
    ///
    /// A new [`TableRowInfo`] instance with calculated indexing properties.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn new(rows: u32) -> Self {
        let bits = if rows == 0 {
            1
        } else {
            let zeros = rows.leading_zeros();
            // Safe: 32 - zeros is always <= 32, fits in u8
            32u8.saturating_sub(zeros as u8)
        };

        Self {
            rows,
            bits,
            is_large: rows > u32::from(u16::MAX),
        }
    }
}

/// Comprehensive metadata and size information for all .NET metadata tables.
///
/// This structure maintains detailed information about table sizes, heap properties,
/// and coded index calculations for an entire .NET assembly. It serves as the central
/// repository for layout information needed to correctly parse metadata structures.
///
/// ## Core Functionality
///
/// - **Table Sizing**: Tracks row counts and determines index sizes for all metadata tables
/// - **Heap Information**: Stores heap size flags that control string/GUID/blob index widths
/// - **Coded Index Caching**: Pre-calculates and caches coded index sizes for performance
///
/// ## Layout Determination
///
/// The .NET metadata format uses variable-width indices to optimize space:
///
/// ```text
/// Table Index Sizes:
/// - Tables with ≤65535 rows → 2-byte indices
/// - Tables with >65535 rows → 4-byte indices
///
/// Heap Index Sizes (from heap size flags):
/// - #String heap → 2 or 4 bytes
/// - #GUID heap   → 2 or 4 bytes  
/// - #Blob heap   → 2 or 4 bytes
/// ```
///
/// ## Related Types
///
/// - [`crate::metadata::tables::types::TableRowInfo`] - Individual table metadata
/// - [`crate::metadata::tables::types::TableInfoRef`] - Arc-wrapped shared reference
/// - [`crate::metadata::tables::types::CodedIndexType`] - Coded index type definitions
/// - [`crate::metadata::tables::types::TableId`] - Table identifier enumeration
#[derive(Clone, Default)]
pub struct TableInfo {
    /// Metadata for each table type, indexed by [`TableId`] as usize.
    ///
    /// Contains row count and indexing information for all possible metadata tables.
    /// Empty tables may have default values if not present in the assembly.
    rows: Vec<TableRowInfo>,

    /// Cached bit sizes for coded index types, indexed by [`CodedIndexType`] as usize.
    ///
    /// Pre-calculated during construction to avoid repeated computation during parsing.
    /// Values represent the number of bits needed to encode coded indices of each type.
    coded_indexes: Vec<u8>,

    /// Whether the #String heap requires 4-byte indices instead of 2-byte.
    ///
    /// Determined by bit 0 of the heap size flags in the metadata tables header.
    /// When `true`, all string heap references use 4 bytes; when `false`, 2 bytes.
    is_large_index_str: bool,

    /// Whether the #GUID heap requires 4-byte indices instead of 2-byte.
    ///
    /// Determined by bit 1 of the heap size flags in the metadata tables header.
    /// When `true`, all GUID heap references use 4 bytes; when `false`, 2 bytes.
    is_large_index_guid: bool,

    /// Whether the #Blob heap requires 4-byte indices instead of 2-byte.
    ///
    /// Determined by bit 2 of the heap size flags in the metadata tables header.
    /// When `true`, all blob heap references use 4 bytes; when `false`, 2 bytes.
    is_large_index_blob: bool,

    /// Every index column is four bytes wide, whatever the row counts and heap sizes say.
    ///
    /// The CLR reads uncompressed (`#-`) tables this way when the stream directory also has
    /// a `#JTD` stream, its "minimal delta" marker. The stream directory decides it, so the
    /// caller of [`TableInfo::new`] passes it; the tables header does not record it.
    wide_columns: bool,

    /// Bit mask of the tables this `TableInfo` actually describes.
    ///
    /// [`Self::row_count`] cannot answer this: it returns 0 both for a table that is present
    /// and empty and for one this `TableInfo` says nothing about. Those are different facts,
    /// and code that bounds a row against `row_count` needs the second one - a `TableInfo`
    /// reconstructed for a writer round-trip or a unit test describes only the tables it was
    /// given, so treating "not described" as "has no rows" rejects valid data.
    declared: u64,
}

/// Shared reference to a [`TableInfo`] structure for efficient multi-threaded access.
///
/// This type alias provides a convenient way to share table information across
/// multiple threads without copying the underlying data. The Arc wrapper ensures
/// thread-safe reference counting while maintaining immutability of the table metadata.
pub type TableInfoRef = Arc<TableInfo>;

impl TableInfo {
    /// Bit mask of every table id that has a [`TableId`] variant.
    ///
    /// Derived from the enum itself rather than written out, so it cannot drift as tables are
    /// added. The `#~` valid mask is checked against this before any row count is read; see
    /// [`Self::new`].
    fn known_table_mask() -> u64 {
        TableId::iter().fold(0u64, |mask, table_id| {
            // Every discriminant is below 64 (the mask is a `u64` by specification), so the
            // shift is always defined.
            mask | (1u64 << (table_id as usize))
        })
    }

    /// Constructs a new `TableInfo` from metadata tables header data.
    ///
    /// Parses the metadata tables header to extract table row counts and heap size flags,
    /// then calculates all necessary index sizes and coded index bit requirements.
    ///
    /// ## Format Overview
    ///
    /// The metadata tables header contains:
    /// ```text
    /// Offset | Size | Description
    /// -------|------|-------------
    /// 0      | 4    | Reserved (should be 0)
    /// 4      | 1    | Major version
    /// 5      | 1    | Minor version
    /// 6      | 1    | Heap size flags
    /// 7      | 1    | Reserved (should be 1)
    /// 8      | 8    | Valid table mask (bit vector)
    /// 16     | 8    | Sorted table mask
    /// 24+    | 4×N  | Row counts for valid tables
    /// ```
    ///
    /// ## Arguments
    ///
    /// * `data` - Raw metadata tables header bytes starting from the tables header
    /// * `valid_bitvec` - 64-bit mask indicating which tables are present (bit N = `TableId` N)
    /// * `wide_columns` - Every index column is four bytes wide, as the CLR reads uncompressed
    ///   (`#-`) tables beside a `#JTD` stream (see the `wide_columns` field)
    ///
    /// ## Returns
    ///
    /// A fully initialized [`TableInfo`] with calculated index sizes and cached coded index information.
    ///
    /// ## Errors
    ///
    /// - [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] - Insufficient data to read required header fields
    ///
    /// ## Reference
    ///
    /// * [ECMA-335 Partition II, Section 24.2.6](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - #~ Stream
    pub fn new(data: &[u8], valid_bitvec: u64, wide_columns: bool) -> Result<Self> {
        Self::read(data, valid_bitvec, wide_columns, None)
    }

    /// Reads a Portable PDB's tables header: its own tables' row counts from `data`, and the
    /// row counts of the assembly tables its columns index from `external_rows` (the `#Pdb`
    /// stream's, by [`TableId`]), so an index into a type-system table the PDB does not hold
    /// is as wide as that table needs.
    ///
    /// # Errors
    ///
    /// As [`TableInfo::new`].
    pub fn with_external_rows(
        data: &[u8],
        valid_bitvec: u64,
        external_rows: &[u32; 64],
    ) -> Result<Self> {
        Self::read(data, valid_bitvec, false, Some(external_rows))
    }

    /// Reads the row counts `data` declares, and takes those of the tables it does not
    /// declare from `external_rows`.
    fn read(
        data: &[u8],
        valid_bitvec: u64,
        wide_columns: bool,
        external_rows: Option<&[u32; 64]>,
    ) -> Result<Self> {
        // Reject bits that name no table before reading a single row count.
        //
        // `TableId` covers 0x00-0x2C and 0x30-0x37; the gaps at 0x2D-0x2F and 0x38-0x3F have no
        // variant. The loop below consumes a `u32` only for bits that map to a known `TableId`,
        // but `TablesHeader::from` computes where table data starts from
        // `valid_bitvec.count_ones()` row-count words (plus the ExtraData word when HeapSizes
        // sets 0x40) - which counts them. A single gap bit therefore
        // makes the two disagree about how many row-count words the header holds, shifting
        // every subsequent row count onto the wrong table and mis-locating the table data.
        // Rejecting the mask keeps them in agreement by construction, rather than requiring
        // both to implement the same tolerance.
        let unknown = valid_bitvec & !Self::known_table_mask();
        if unknown != 0 {
            return Err(malformed_error!(
                "#~ valid mask names {} table(s) that do not exist (unknown bits 0x{:016X})",
                unknown.count_ones(),
                unknown
            ));
        }

        let table_info_len = (TableId::CustomDebugInformation as usize)
            .checked_add(1)
            .ok_or_else(|| malformed_error!("Table info size overflow"))?;
        let mut table_info = vec![TableRowInfo::default(); table_info_len];
        let mut next_row_offset = 24;

        for table_id in TableId::iter() {
            if data.len() < next_row_offset {
                return Err(out_of_bounds_error!());
            }

            if (valid_bitvec & (1 << table_id as usize)) == 0 {
                continue;
            }

            let row_count = read_le_at::<u32>(data, &mut next_row_offset)?;
            if row_count == 0 {
                // Empty tables should be omitted during compliation and not being present in a valid sample
                // return Err(Malformed)
                continue;
            }

            let slot = table_info
                .get_mut(table_id as usize)
                .ok_or(out_of_bounds_error!())?;
            *slot = TableRowInfo::new(row_count);
        }

        // A Portable PDB's columns index the assembly's tables, which the PDB does not hold
        if let Some(external_rows) = external_rows {
            for table_id in TableId::iter() {
                let rows = external_rows.get(table_id as usize).copied().unwrap_or(0);
                if rows != 0 && valid_bitvec & (1 << table_id as usize) == 0 {
                    let slot = table_info
                        .get_mut(table_id as usize)
                        .ok_or(out_of_bounds_error!())?;
                    *slot = TableRowInfo::new(rows);
                }
            }
        }

        let heap_size_flags = read_le::<u8>(data.get(6..).ok_or(out_of_bounds_error!())?)?;
        let mut table_info = TableInfo {
            rows: table_info,
            // Every bit survived the check above, so the mask is exactly the tables the
            // header declares.
            declared: valid_bitvec,
            coded_indexes: vec![0; CodedIndexType::COUNT],
            is_large_index_str: heap_size_flags & 1 == 1,
            is_large_index_guid: heap_size_flags & 2 == 2,
            is_large_index_blob: heap_size_flags & 4 == 4,
            wide_columns,
        };

        table_info.calculate_coded_index_bits();

        Ok(table_info)
    }

    #[cfg(any(test, feature = "testkit"))]
    /// Special constructor for unit tests with controlled table configuration.
    ///
    /// This method allows precise control over table sizes and heap configurations
    /// for testing scenarios without requiring actual metadata header data.
    ///
    /// ## Arguments
    ///
    /// * `valid_tables` - Slice of (table_id, row_count) pairs for tables to populate
    /// * `large_str` - Whether the #String heap uses 4-byte indices
    /// * `large_blob` - Whether the #Blob heap uses 4-byte indices  
    /// * `large_guid` - Whether the #GUID heap uses 4-byte indices
    ///
    /// ## Returns
    ///
    /// A [`TableInfo`] instance configured with the specified parameters and
    /// calculated coded index sizes.
    pub fn new_test(
        valid_tables: &[(TableId, u32)],
        large_str: bool,
        large_blob: bool,
        large_guid: bool,
    ) -> Self {
        let mut table_info = TableInfo {
            rows: vec![
                TableRowInfo::default();
                (TableId::CustomDebugInformation as usize).saturating_add(1)
            ],
            declared: 0,
            coded_indexes: vec![0; CodedIndexType::COUNT],
            is_large_index_str: large_str,
            is_large_index_guid: large_guid,
            is_large_index_blob: large_blob,
            wide_columns: false,
        };

        for valid_table in valid_tables {
            if let Some(row) = table_info.rows.get_mut(valid_table.0 as usize) {
                *row = TableRowInfo::new(valid_table.1);
            }
            table_info.declared |= 1u64 << (valid_table.0 as usize);
        }

        table_info.calculate_coded_index_bits();
        table_info
    }

    /// Decodes a coded index value into its component table and row index.
    ///
    /// Coded indices pack both a table identifier and row index into a single value
    /// using a tag-based encoding scheme. The lower bits contain a tag that identifies
    /// which table the index refers to, while the upper bits contain the actual row index.
    ///
    /// ## Encoding Format
    ///
    /// ```text
    /// Coded Index Value:
    /// ┌─────────────────────┬────────────┐
    /// │     Row Index       │    Tag     │
    /// │   (upper bits)      │(lower bits)│
    /// └─────────────────────┴────────────┘
    ///
    /// Tag bits = CodedIndexType::tag_bits (enough for every tag, unused ones included)
    /// Row bits = remaining bits
    /// ```
    ///
    /// ## Arguments
    ///
    /// * `value` - The encoded coded index value to decode
    /// * `coded_index_type` - The type of coded index being decoded (determines table union)
    ///
    /// ## Returns
    ///
    /// `Some((table, row))`, or `None` when the tag is one this coded index assigns to no
    /// table: a value past its last tag, or `CustomAttributeType`'s unused tags 0, 1 and 4.
    /// The CLR reads such an index as a null reference.
    ///
    /// ## Reference
    ///
    /// * [ECMA-335 Partition II, Section 24.2.6](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Coded Indices
    pub fn decode_coded_index(
        &self,
        value: u32,
        coded_index_type: CodedIndexType,
    ) -> Option<(TableId, u32)> {
        let tag_bits = coded_index_type.tag_bits();
        let tag_mask = (1u32 << tag_bits).saturating_sub(1);
        let table = coded_index_type.table_for_tag(value & tag_mask)?;
        Some((table, value >> tag_bits))
    }

    /// Encodes a table identifier and row index into a coded index value.
    ///
    /// This method performs the reverse operation of `decode_coded_index`, combining
    /// a table identifier and row index into a single encoded value using the tag-based
    /// encoding scheme defined by ECMA-335.
    ///
    /// ## Encoding Format
    ///
    /// ```text
    /// Coded Index Value:
    /// ┌─────────────────────┬────────────┐
    /// │     Row Index       │    Tag     │
    /// │   (upper bits)      │(lower bits)│
    /// └─────────────────────┴────────────┘
    ///
    /// Tag bits = ceil(log2(number_of_tables_in_union))
    /// Row bits = remaining bits
    /// ```
    ///
    /// ## Arguments
    ///
    /// * `table_id` - The [`TableId`] identifying which table the index refers to
    /// * `row` - The 1-based row index within the specified table
    /// * `coded_index_type` - The type of coded index being encoded (determines table union)
    ///
    /// ## Returns
    ///
    /// The encoded coded index value that can be written to metadata.
    ///
    /// ## Errors
    ///
    /// - [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] - Table ID is not valid for the specified coded index type
    ///
    /// ## Reference
    ///
    /// * [ECMA-335 Partition II, Section 24.2.6](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Coded Indices
    pub fn encode_coded_index(
        &self,
        table_id: TableId,
        row: u32,
        coded_index_type: CodedIndexType,
    ) -> Result<u32> {
        let tag = coded_index_type
            .tag_for_table(table_id)
            .ok_or(out_of_bounds_error!())?;
        let tag_bits = coded_index_type.tag_bits();

        // Encode: (row << tag_bits) | tag
        //
        // A row too large for the bits left after the tag would shift its high bits off the
        // top and encode a *different* row, so it is rejected rather than silently truncated.
        // Round-tripping the shift is the check.
        let encoded = row
            .checked_shl(u32::from(tag_bits))
            .filter(|shifted| (shifted >> tag_bits) == row)
            .ok_or_else(|| {
                malformed_error!(
                    "Row {} does not fit a {}-bit-tagged coded index",
                    row,
                    tag_bits
                )
            })?;

        Ok(encoded | tag)
    }

    /// Checks whether a specific table requires large (4-byte) indices due to size.
    ///
    /// Tables with more than 65535 rows cannot be addressed using 2-byte indices,
    /// requiring all references to that table to use 4-byte indices instead.
    ///
    /// ## Arguments
    ///
    /// * `id` - The [`TableId`] to query for large index requirement
    ///
    /// ## Returns
    ///
    /// `true` if the table has more than 65535 rows and requires 4-byte indices,
    /// `false` if 2-byte indices are sufficient.
    #[must_use]
    pub fn is_large(&self, id: TableId) -> bool {
        self.wide_columns || self.rows.get(id as usize).is_some_and(|info| info.is_large)
    }

    /// Returns whether the #String heap uses large (4-byte) indices.
    ///
    /// The size of string heap indices is determined by heap size flags in the
    /// metadata tables header. Large heaps require 4-byte indices instead of 2-byte.
    ///
    /// ## Returns
    ///
    /// `true` if string heap references use 4 bytes, `false` if they use 2 bytes.
    #[must_use]
    pub fn is_large_str(&self) -> bool {
        self.wide_columns || self.is_large_index_str
    }

    /// Returns whether the #GUID heap uses large (4-byte) indices.
    ///
    /// The size of GUID heap indices is determined by heap size flags in the
    /// metadata tables header. Large heaps require 4-byte indices instead of 2-byte.
    ///
    /// ## Returns
    ///
    /// `true` if GUID heap references use 4 bytes, `false` if they use 2 bytes.
    #[must_use]
    pub fn is_large_guid(&self) -> bool {
        self.wide_columns || self.is_large_index_guid
    }

    /// Returns whether the #Blob heap uses large (4-byte) indices.
    ///
    /// The size of blob heap indices is determined by heap size flags in the
    /// metadata tables header. Large heaps require 4-byte indices instead of 2-byte.
    ///
    /// ## Returns
    ///
    /// `true` if blob heap references use 4 bytes, `false` if they use 2 bytes.
    #[must_use]
    pub fn is_large_blob(&self) -> bool {
        self.wide_columns || self.is_large_index_blob
    }

    /// Returns the byte size of #String heap indices.
    ///
    /// ## Returns
    ///
    /// `4` if the string heap uses large indices, `2` otherwise.
    #[must_use]
    pub fn str_bytes(&self) -> u8 {
        if self.is_large_str() {
            4
        } else {
            2
        }
    }

    /// Returns the byte size of #GUID heap indices.
    ///
    /// ## Returns
    ///
    /// `4` if the GUID heap uses large indices, `2` otherwise.
    #[must_use]
    pub fn guid_bytes(&self) -> u8 {
        if self.is_large_guid() {
            4
        } else {
            2
        }
    }

    /// Returns the byte size of #Blob heap indices.
    ///
    /// ## Returns
    ///
    /// `4` if the blob heap uses large indices, `2` otherwise.
    #[must_use]
    pub fn blob_bytes(&self) -> u8 {
        if self.is_large_blob() {
            4
        } else {
            2
        }
    }

    /// Returns the metadata information for a specific table.
    ///
    /// Provides access to the [`TableRowInfo`] structure containing row count,
    /// bit requirements, and large index status for the specified table.
    ///
    /// ## Arguments
    ///
    /// * `table` - The [`TableId`] for which to retrieve metadata
    ///
    /// ## Returns
    ///
    /// A reference to the [`TableRowInfo`] for the specified table.
    #[must_use]
    pub fn get(&self, table: TableId) -> &TableRowInfo {
        // The `rows` vector is sized to cover every TableId variant, so this lookup
        // is always in range. Fall back to a static default to keep the lint happy
        // and to avoid panics on malformed inputs.
        static DEFAULT: TableRowInfo = TableRowInfo {
            rows: 0,
            bits: 1,
            is_large: false,
        };
        self.rows.get(table as usize).unwrap_or(&DEFAULT)
    }

    /// Returns the number of bits required to represent an index into a specific table.
    ///
    /// This value represents the minimum number of bits needed to address any valid
    /// row in the specified table. It's calculated as `ceil(log2(row_count))` or 1
    /// for empty tables.
    ///
    /// ## Arguments
    ///
    /// * `table_id` - The [`TableId`] for which to calculate the index bit size
    ///
    /// ## Returns
    ///
    /// The number of bits required to represent table indices (1-32).
    #[must_use]
    pub fn table_index_bits(&self, table_id: TableId) -> u8 {
        if self.wide_columns {
            return 32;
        }
        self.rows.get(table_id as usize).map_or(1, |info| info.bits)
    }

    /// Returns the number of bytes required to represent an index into a specific table.
    ///
    /// Converts the bit requirement into actual byte storage size. Tables requiring
    /// more than 16 bits (>65535 rows) use 4-byte indices, otherwise 2-byte indices.
    ///
    /// ## Arguments
    ///
    /// * `table_id` - The [`TableId`] for which to calculate the index byte size
    ///
    /// ## Returns
    ///
    /// Either `2` for small tables or `4` for large tables.
    #[must_use]
    pub fn table_index_bytes(&self, table_id: TableId) -> u8 {
        let bits = self.table_index_bits(table_id);
        if bits > 16 {
            4
        } else {
            2
        }
    }

    /// Returns the cached bit size for a specific coded index type.
    ///
    /// Coded index bit sizes are pre-calculated during [`TableInfo`] construction
    /// and cached for efficient lookup. The size accounts for both the tag bits
    /// (to identify the table) and the row index bits.
    ///
    /// ## Arguments
    ///
    /// * `coded_index_type` - The [`CodedIndexType`] for which to retrieve the cached size
    ///
    /// ## Returns
    ///
    /// The number of bits required to represent coded indices of this type.
    #[must_use]
    pub fn coded_index_bits(&self, coded_index_type: CodedIndexType) -> u8 {
        if self.wide_columns {
            return 32;
        }
        self.coded_indexes
            .get(coded_index_type as usize)
            .copied()
            .unwrap_or(0)
    }

    /// Returns the cached byte size for a specific coded index type.
    ///
    /// Converts the cached bit size into actual byte storage requirements.
    /// Coded indices requiring more than 16 bits use 4-byte storage, otherwise 2-byte.
    ///
    /// ## Arguments
    ///
    /// * `coded_index_type` - The [`CodedIndexType`] for which to retrieve the byte size
    ///
    /// ## Returns
    ///
    /// Either `2` for coded indices that fit in 16 bits or `4` for larger coded indices.
    #[must_use]
    pub fn coded_index_bytes(&self, coded_index_type: CodedIndexType) -> u8 {
        let bits = self.coded_index_bits(coded_index_type);
        if bits > 16 {
            4
        } else {
            2
        }
    }

    /// Calculates the number of bits required for a specific coded index type.
    ///
    /// This internal method computes the bit requirements for coded indices based on:
    /// 1. The maximum table size among all tables in the coded index union
    /// 2. The number of tag bits needed to distinguish between tables
    ///
    /// ## Arguments
    ///
    /// * `coded_index_type` - The [`CodedIndexType`] for which to calculate the size
    ///
    /// ## Returns
    ///
    /// The total number of bits required for coded indices of this type.
    fn calculate_coded_index_size(&self, coded_index_type: CodedIndexType) -> u8 {
        let max_bits = coded_index_type
            .tables()
            .iter()
            .map(|table| self.table_index_bits(*table))
            .max()
            .unwrap_or(1);
        max_bits.saturating_add(coded_index_type.tag_bits())
    }

    /// Calculates and caches the bit sizes required for all coded index types.
    ///
    /// This method is called during [`TableInfo`] construction to pre-compute coded index
    /// sizes for all possible coded index types. The cached values enable fast O(1) lookup
    /// during metadata parsing operations.
    fn calculate_coded_index_bits(&mut self) {
        for coded_index in CodedIndexType::iter() {
            let size = self.calculate_coded_index_size(coded_index);
            if let Some(slot) = self.coded_indexes.get_mut(coded_index as usize) {
                *slot = size;
            }
        }
    }

    /// Returns the heap sizes flags byte as defined in ECMA-335 II.24.2.6.
    ///
    /// This byte encodes which heaps use large (4-byte) indices:
    /// - Bit 0: #Strings heap (large if set)
    /// - Bit 1: #GUID heap (large if set)
    /// - Bit 2: #Blob heap (large if set)
    ///
    /// ## Returns
    ///
    /// The heap sizes flags byte for serialization in the tables stream header.
    ///
    /// ## Examples
    ///
    /// ```no_run
    /// let heap_sizes = table_info.heap_sizes();
    /// // Use in tables stream header serialization
    /// writer.write_all(&[heap_sizes])?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn heap_sizes(&self) -> u8 {
        let mut flags = 0u8;
        if self.is_large_index_str {
            flags |= 0x01;
        }
        if self.is_large_index_guid {
            flags |= 0x02;
        }
        if self.is_large_index_blob {
            flags |= 0x04;
        }
        flags
    }

    /// Returns the row count for a specific table.
    ///
    /// ## Arguments
    ///
    /// * `table_id` - The [`TableId`] for which to retrieve the row count
    ///
    /// ## Returns
    ///
    /// The number of rows in the specified table, or 0.
    ///
    /// **A 0 here is ambiguous**: it means either "this table is present and empty" or "this
    /// `TableInfo` does not describe this table". Do not bound a row index against this value
    /// without first asking [`Self::is_declared`] - a `TableInfo` built for a writer
    /// round-trip or a test describes only some tables, and rejecting rows that reference the
    /// others would reject valid metadata.
    #[must_use]
    pub fn row_count(&self, table_id: TableId) -> u32 {
        self.rows.get(table_id as usize).map_or(0, |info| info.rows)
    }

    /// Whether this `TableInfo` describes the given table at all.
    ///
    /// See [`Self::row_count`] for why the two questions are separate.
    #[must_use]
    pub fn is_declared(&self, table_id: TableId) -> bool {
        self.declared & (1u64 << (table_id as usize)) != 0
    }

    /// Creates a new `TableInfo` with modified row counts for specified tables.
    ///
    /// This method is used when writing assemblies with modified table sizes (e.g., after
    /// row deletions or insertions). The new `TableInfo` will have recalculated coded index
    /// sizes based on the updated row counts.
    ///
    /// ## Arguments
    ///
    /// * `new_counts` - Iterator of (table_id, new_row_count) pairs for tables to update.
    ///   Tables not in this iterator retain their original row counts.
    ///
    /// ## Returns
    ///
    /// A new [`TableInfo`] instance with updated row counts and recalculated coded index sizes.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// use std::collections::HashMap;
    /// use dotscope::metadata::tables::TableId;
    ///
    /// let mut new_counts = HashMap::new();
    /// new_counts.insert(TableId::TypeDef, 50);
    /// new_counts.insert(TableId::MethodDef, 100);
    ///
    /// let modified_info = original_info.with_modified_row_counts(new_counts.iter().map(|(k, v)| (*k, *v)));
    /// ```
    #[must_use]
    pub fn with_modified_row_counts(
        &self,
        new_counts: impl Iterator<Item = (TableId, u32)>,
    ) -> TableInfo {
        let mut rows = self.rows.clone();
        for (table_id, count) in new_counts {
            if let Some(slot) = rows.get_mut(table_id as usize) {
                *slot = TableRowInfo::new(count);
            }
        }

        let mut new_info = TableInfo {
            rows,
            // A row count changing does not change which tables are described.
            declared: self.declared,
            coded_indexes: vec![0; CodedIndexType::COUNT],
            is_large_index_str: self.is_large_index_str,
            is_large_index_guid: self.is_large_index_guid,
            is_large_index_blob: self.is_large_index_blob,
            wide_columns: false,
        };

        new_info.calculate_coded_index_bits();
        new_info
    }

    /// Returns a copy with heap index widths derived from the given **output** heap sizes.
    ///
    /// ECMA-335 II.24.2.6 selects a 4-byte heap index once a heap exceeds 0xFFFF bytes. The
    /// widths on `self` come from the *input* file's `HeapSizes` byte and are copied verbatim by
    /// [`with_modified_row_counts`](Self::with_modified_row_counts), so a writer that appends
    /// past the threshold - new type and method names, decrypted literals, rebuilt signatures -
    /// keeps emitting 2-byte indices while resolving offsets that no longer fit them.
    ///
    /// Call this with the byte counts actually written for `#Strings`, `#GUID` and `#Blob`,
    /// before the tables stream is laid out.
    ///
    /// # Arguments
    ///
    /// * `strings_bytes` - Size of the emitted `#Strings` heap.
    /// * `guid_bytes` - Size of the emitted `#GUID` heap.
    /// * `blob_bytes` - Size of the emitted `#Blob` heap.
    #[must_use]
    pub fn with_modified_heap_sizes(
        &self,
        strings_bytes: usize,
        guid_bytes: usize,
        blob_bytes: usize,
    ) -> TableInfo {
        /// Offsets are indices into the heap, so a heap of exactly 0x10000 bytes still needs a
        /// 4-byte index to address its last entry.
        const LARGE_HEAP_THRESHOLD: usize = 0xFFFF;

        let mut new_info = TableInfo {
            rows: self.rows.clone(),
            declared: self.declared,
            coded_indexes: vec![0; CodedIndexType::COUNT],
            // Widths only ever widen here: an input that already declared 4-byte indices keeps
            // them, because existing rows were read at that width.
            is_large_index_str: self.is_large_index_str || strings_bytes > LARGE_HEAP_THRESHOLD,
            is_large_index_guid: self.is_large_index_guid || guid_bytes > LARGE_HEAP_THRESHOLD,
            is_large_index_blob: self.is_large_index_blob || blob_bytes > LARGE_HEAP_THRESHOLD,
            wide_columns: false,
        };

        new_info.calculate_coded_index_bits();
        new_info
    }
}

#[cfg(test)]
mod heap_size_tests {
    use super::*;

    /// A heap that grew past 0xFFFF must promote its index to 4 bytes.
    ///
    /// Without this the emitted `HeapSizes` byte keeps the *input* file's widths, every
    /// heap-reference field is written 2 bytes wide, and any offset at or above 0x10000 is
    /// masked - producing a file that parses cleanly while its names and signatures point at
    /// arbitrary earlier heap positions.
    #[test]
    fn heap_index_widens_past_the_threshold() {
        let base = TableInfo::new_test(&[], false, false, false);

        let widened = base.with_modified_heap_sizes(0x1_0000, 0, 0);
        assert!(widened.is_large_str(), "#Strings must widen");
        assert!(!widened.is_large_guid());
        assert!(!widened.is_large_blob());

        let widened = base.with_modified_heap_sizes(0, 0x20_0000, 0x1_0000);
        assert!(!widened.is_large_str());
        assert!(widened.is_large_guid(), "#GUID must widen");
        assert!(widened.is_large_blob(), "#Blob must widen");
    }

    /// Exactly at the boundary the 2-byte index still addresses every offset.
    #[test]
    fn heap_index_stays_small_at_the_boundary() {
        let base = TableInfo::new_test(&[], false, false, false);
        let same = base.with_modified_heap_sizes(0xFFFF, 0xFFFF, 0xFFFF);

        assert!(!same.is_large_str());
        assert!(!same.is_large_guid());
        assert!(!same.is_large_blob());
    }

    /// Widths never narrow: existing rows in the input were read at the declared width.
    #[test]
    fn heap_index_never_narrows() {
        let base = TableInfo::new_test(&[], true, true, true);
        let narrowed = base.with_modified_heap_sizes(16, 16, 16);

        assert!(narrowed.is_large_str());
        assert!(narrowed.is_large_guid());
        assert!(narrowed.is_large_blob());
    }

    /// A Portable PDB's columns index the assembly's tables by the `#Pdb` stream's row
    /// counts: past 65535 MethodDef rows a LocalScope's method index is four bytes, and the
    /// tables the stream declares keep their own counts.
    #[test]
    fn external_rows_size_indexes_into_the_assembly() {
        // A tables header declaring one LocalScope row
        let mut header = vec![0u8; 24];
        let valid = 1u64 << (TableId::LocalScope as u8);
        header[8..16].copy_from_slice(&valid.to_le_bytes());
        header.extend_from_slice(&1u32.to_le_bytes());

        let mut external = [0u32; 64];
        external[TableId::MethodDef as usize] = 70_000;
        let wide = TableInfo::with_external_rows(&header, valid, &external).unwrap();
        assert_eq!(wide.table_index_bytes(TableId::MethodDef), 4);
        assert_eq!(wide.row_count(TableId::LocalScope), 1);

        external[TableId::MethodDef as usize] = 100;
        let narrow = TableInfo::with_external_rows(&header, valid, &external).unwrap();
        assert_eq!(narrow.table_index_bytes(TableId::MethodDef), 2);
    }
}

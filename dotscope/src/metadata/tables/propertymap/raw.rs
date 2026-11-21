//! # `PropertyMap` Raw Implementation
//!
//! This module provides the raw variant of `PropertyMap` table entries with unresolved
//! indexes for initial parsing and memory-efficient storage.

use std::sync::Arc;

use crate::{
    metadata::{
        tables::{
            MemberRanges, PropertyList, PropertyMap, PropertyMapEntry, PropertyMapEntryRc,
            PropertyPtrMap, TableId, TableInfoRef, TableRow,
        },
        token::Token,
        typesystem::TypeRegistry,
    },
    Result,
};

/// Raw representation of a `PropertyMap` table entry from the .NET metadata.
///
/// The `PropertyMap` table maps types to their properties, establishing the relationship between
/// [`TypeDefRaw`](crate::metadata::tables::TypeDefRaw) entries and their associated
/// [`Property`](crate::metadata::tables::Property) entries. Each entry defines a contiguous
/// range of properties belonging to a specific type.
///
/// ## Metadata Table Information
/// - **Table ID**: `0x15` (21 decimal)
/// - **Token Type**: `0x15000000` + RID
/// - **Purpose**: Associates types with their property lists
///
/// ## Structure Layout
/// The table entry contains references to both the parent type and the starting position
/// in the `Property` table, with the range determined by looking at the next `PropertyMap` entry
/// or the end of the `Property` table.
///
/// ## See Also
/// - [`crate::metadata::tables::PropertyMapEntry`] - Resolved owned variant
/// - [ECMA-335 §II.22.35](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/) - `PropertyMap` table specification
#[derive(Clone, Debug)]
pub struct PropertyMapRaw {
    /// The 1-based row identifier within the `PropertyMap` table.
    pub rid: u32,

    /// The metadata token for this `PropertyMap` entry.
    ///
    /// Format: `0x15000000 | RID` where RID is the 1-based row index.
    pub token: Token,

    /// Byte offset of this entry within the metadata stream.
    pub offset: usize,

    /// Index into the [`TypeDefRaw`](crate::metadata::tables::TypeDefRaw) table indicating
    /// the parent type that owns the properties.
    ///
    /// This is a 1-based index that must be combined with the `TypeDef` token prefix
    /// (`0x02000000`) to create a valid `TypeDef` token.
    pub parent: u32,

    /// Index into the [`Property`](crate::metadata::tables::Property) table indicating
    /// the first property belonging to the parent type.
    ///
    /// The range of properties is determined by comparing this value with the
    /// `property_list` of the next `PropertyMap` entry, or extends to the end of
    /// the `Property` table if this is the last entry.
    pub property_list: u32,
}

impl PropertyMapRaw {
    /// Resolves the property list range for this `PropertyMap` entry.
    ///
    /// This helper method determines the range of properties belonging to the parent type
    /// by calculating the start and end indices within the `Property` table. The range is
    /// determined by this entry's `property_list` value and the next entry's value (or
    /// the end of the `Property` table for the last entry).
    ///
    /// ## Property Resolution Logic
    /// 1. **Direct Properties**: When no `PropertyPtr` table exists, properties are accessed directly
    /// 2. **Indirect Properties**: When `PropertyPtr` table exists, properties are accessed through indirection
    /// 3. **Range Calculation**: End index is determined by the next `PropertyMap` entry or table end,
    ///    read from `ranges`, which holds the runs of the whole table clamped to the `Property`
    ///    table and made non-overlapping (see [`MemberRanges`]); whether `PropertyPtr` is used is
    ///    decided there too, by whether that table has rows
    ///
    /// ## Arguments
    /// * `properties` - Map of all resolved `Property` entries for lookup
    /// * `property_ptr` - Map of `PropertyPtr` entries for indirection resolution
    /// * `ranges` - The normalized `PropertyList` runs of the whole `PropertyMap` table
    ///   ([`TablesHeader::member_ranges`](crate::metadata::streams::TablesHeader::member_ranges)
    ///   with [`MemberList::PropertyMapProperties`](crate::metadata::tables::MemberList::PropertyMapProperties))
    ///
    /// ## Returns
    /// Returns a [`crate::metadata::tables::PropertyList`] containing the resolved
    /// `Property` entries for this type, or an empty list if no properties exist.
    ///
    /// ## Errors
    /// - Returns error if a position in the run names a `PropertyPtr` row that is not loaded
    /// - Returns error if a position (or its `PropertyPtr` entry) names a property that is not
    ///   loaded
    fn resolve_property_list(
        &self,
        properties: &PropertyMap,
        property_ptr: &PropertyPtrMap,
        ranges: &MemberRanges,
    ) -> Result<PropertyList> {
        let property_list = PropertyList::new();
        for property in ranges.members(self.rid, property_ptr, |ptr| ptr.property, properties) {
            _ = property_list.push(property?);
        }
        Ok(property_list)
    }

    /// Converts this raw `PropertyMap` entry into a fully resolved owned entry.
    ///
    /// This method creates a [`crate::metadata::tables::PropertyMapEntry`]
    /// that contains the resolved parent type reference and the complete list of `Property`
    /// entries associated with this type. The conversion resolves all table indices and
    /// creates owned references to the data.
    ///
    /// ## Arguments
    /// * `types` - The [`crate::metadata::typesystem::TypeRegistry`] for resolving parent types
    /// * `properties` - Map of all resolved `Property` entries for lookup
    /// * `property_ptr` - Map of `PropertyPtr` entries for indirection resolution
    /// * `ranges` - The normalized `PropertyList` runs of the whole `PropertyMap` table (see
    ///   [`MemberRanges`])
    ///
    /// ## Returns
    /// Returns an [`std::sync::Arc`]-wrapped [`crate::metadata::tables::PropertyMapEntry`]
    /// containing the fully resolved data, suitable for long-term storage and sharing.
    ///
    /// ## Errors
    /// - Returns error if the parent type cannot be resolved from the `TypeRegistry`
    /// - Returns error if property list resolution fails
    /// - Returns error if any referenced `Property` entries are missing
    pub fn to_owned(
        &self,
        types: &TypeRegistry,
        properties: &PropertyMap,
        property_ptr: &PropertyPtrMap,
        ranges: &MemberRanges,
    ) -> Result<PropertyMapEntryRc> {
        let parent = match types.get(&Token::new(self.parent | 0x0200_0000)) {
            Some(parent_type) => parent_type.into(),
            None => {
                return Err(malformed_error!(
                    "Failed to resolve parent type - {}",
                    self.parent | 0x0200_0000
                ))
            }
        };

        Ok(Arc::new(PropertyMapEntry {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            parent,
            properties: self.resolve_property_list(properties, property_ptr, ranges)?,
        }))
    }

    /// Applies this `PropertyMap` entry to its parent type in the type registry.
    ///
    /// This method resolves the property list for this entry and adds all the properties
    /// to the parent type's property collection. This is used during metadata loading to
    /// populate types with their associated properties.
    ///
    /// ## Application Process
    /// 1. **Property Resolution**: Determines and resolves the property range for this type
    /// 2. **Parent Lookup**: Finds the parent type in the `TypeRegistry`
    /// 3. **Property Assignment**: Adds all resolved properties to the parent type
    ///
    /// ## Arguments
    /// * `types` - The [`crate::metadata::typesystem::TypeRegistry`] containing all parsed types
    /// * `properties` - Map of all resolved Property entries for lookup
    /// * `property_ptr` - Map of `PropertyPtr` entries for indirection resolution
    /// * `ranges` - The normalized `PropertyList` runs of the whole `PropertyMap` table (see
    ///   [`MemberRanges`])
    ///
    /// ## Errors
    /// - Returns error if the property list resolution fails
    /// - Returns error if the parent type cannot be found in the `TypeRegistry`
    pub fn apply(
        &self,
        types: &TypeRegistry,
        properties: &PropertyMap,
        property_ptr: &PropertyPtrMap,
        ranges: &MemberRanges,
    ) -> Result<()> {
        let property_list = self.resolve_property_list(properties, property_ptr, ranges)?;

        match types.get(&Token::new(self.parent | 0x0200_0000)) {
            Some(entry) => {
                for (_, property) in property_list.iter() {
                    _ = entry.properties.push(property.clone());
                }
                Ok(())
            }
            None => Err(malformed_error!(
                "Failed to resolve parent - {}",
                self.parent | 0x0200_0000
            )),
        }
    }
}

impl TableRow for PropertyMapRaw {
    /// Calculates the byte size of a `PropertyMap` table row.
    ///
    /// The size depends on whether the `TypeDef` and Property tables use 2-byte or 4-byte indices,
    /// which is determined by the number of rows in each table.
    ///
    /// ## Size Calculation
    /// - **parent**: 2 or 4 bytes (depending on `TypeDef` table size)
    /// - **`property_list`**: 2 or 4 bytes (depending on Property table size)
    ///
    /// ## Arguments
    /// * `sizes` - Table size information for determining index sizes
    ///
    /// ## Returns
    /// The total byte size of a `PropertyMap` table row (4 or 8 bytes).
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* parent */        sizes.table_index_bytes(TableId::TypeDef)
            /* property_list */ .saturating_add(sizes.table_index_bytes(TableId::Property))

        )
    }
}

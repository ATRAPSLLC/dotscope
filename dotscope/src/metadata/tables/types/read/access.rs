//! Safe table access trait for type-safe metadata table retrieval.
//!
//! This module defines the `TableAccess` trait which provides a safe, ergonomic
//! way to access metadata tables without requiring both type parameters and table IDs.
//! This eliminates the need for unsafe code in table access while maintaining
//! type safety and performance.

use crate::metadata::tables::{MetadataTable, RowReadable};

/// Trait for safe, type-safe access to metadata tables.
///
/// This trait provides a clean interface for accessing metadata tables using only
/// the row type, automatically mapping to the correct table type. This eliminates
/// the unsafe code previously required and provides a more ergonomic API.
///
/// # Usage
///
/// ```rust
/// use dotscope::metadata::{streams::TablesHeader, tables::TypeDefRaw};
///
/// # fn example(tables: &TablesHeader) -> dotscope::Result<()> {
/// // Type-safe access - no table ID needed
/// if let Some(typedef_table) = tables.table::<TypeDefRaw>() {
///     // Iteration yields `Result<TypeDefRaw>`: a row that fails to parse is reported
///     // rather than silently ending the iteration.
///     for type_def in typedef_table.iter().take(5) {
///         let type_def = type_def?;
///         println!("Type: {}", type_def.type_name);
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub trait TableAccess<'a, T: RowReadable> {
    /// Retrieve a table of the specified type if present.
    ///
    /// # Returns
    /// * `Some(&MetadataTable<T>)` - Reference to the table if present
    /// * `None` - If the table is not present in this assembly
    fn table(&'a self) -> Option<&'a MetadataTable<'a, T>>;
}

/// Generate TableAccess trait implementations for metadata tables.
///
/// This macro creates type-safe implementations of the TableAccess trait,
/// mapping each row type to its corresponding TableData variant and TableId.
/// This eliminates the need for unsafe code while maintaining performance.
///
/// # Arguments
/// * `$raw` - The raw row type (e.g., TypeDefRaw)
/// * `$id` - The TableId variant (e.g., TableId::TypeDef)
/// * `$variant` - The TableData variant (e.g., TypeDef)
///
/// # Example
/// ```text
/// impl_table_access!(TypeDefRaw, TableId::TypeDef, TypeDef);
/// impl_table_access!(MethodDefRaw, TableId::MethodDef, MethodDef);
/// ```
#[macro_export]
macro_rules! impl_table_access {
    ($raw:ty, $id:expr, $variant:ident) => {
        impl<'a> TableAccess<'a, $raw> for TablesHeader<'a> {
            fn table(&'a self) -> Option<&'a MetadataTable<'a, $raw>> {
                match self.tables.get($id as usize)? {
                    Some(TableData::$variant(table)) => Some(table),
                    _ => None,
                }
            }
        }
    };
}

/// Generate the complete match expression for creating metadata tables in `TablesHeader::add_table()`.
///
/// This macro eliminates the repetitive match arm patterns that would otherwise
/// require ~380 lines of nearly identical code. It generates a complete match expression
/// that handles all table types, where each arm:
/// 1. Creates a `MetadataTable` of the specified type
/// 2. Updates the offset by the table's size
/// 3. Wraps the table in the appropriate `TableData` variant
///
/// # Arguments
/// * `$table_type_var` - The variable containing the `TableId` to match against
/// * `$data` - The data slice to parse from
/// * `$rows` - The number of rows in the table
/// * `$info` - The `TableInfo` for column size calculation
/// * `$offset` - Mutable reference to the current offset
/// * `$(($id:path, $raw:ty, $variant:ident)),*` - List of (TableId variant, Raw type, TableData variant) tuples
///
/// # Size Calculation
/// The macro casts `table.size()` (which returns `u64`) to `usize` for offset arithmetic.
/// This is safe because:
/// - PE files are limited to ~4GB, constraining maximum metadata size
/// - On 64-bit systems, `usize` can hold any valid table size
/// - On 32-bit systems, the 4GB PE limit ensures no truncation occurs
///
/// # Example
/// ```text
/// let table = create_table_match!(
///     table_type, data, t_info.rows, self.info.clone(), current_offset,
///     (TableId::Module, ModuleRaw, Module),
///     (TableId::TypeRef, TypeRefRaw, TypeRef),
///     // ... additional entries
/// );
/// ```
#[macro_export]
macro_rules! create_table_match {
    ($table_type_var:expr, $data:expr, $rows:expr, $info:expr, $offset:expr, $(($id:path, $raw:ty, $variant:ident)),* $(,)?) => {
        match $table_type_var {
            $(
                $id => {
                    let table = MetadataTable::<$raw>::new($data, $rows, $info.clone())?;
                    *$offset += table.size() as usize;
                    TableData::$variant(table)
                }
            )*
        }
    };
}

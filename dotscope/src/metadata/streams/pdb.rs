//! The Portable PDB `#Pdb` stream.
//!
//! A Portable PDB's metadata holds the debug tables (Document, MethodDebugInformation, ...),
//! and their columns name rows of the assembly's own tables: a LocalScope's method, a custom
//! debug information row's parent. Those type-system tables are not in the PDB, so the
//! `#Pdb` stream records how many rows each has, and the PDB's tables size their indexes into
//! them by those counts.
//!
//! # Layout
//!
//! | Field | Size | Meaning |
//! |-------|------|---------|
//! | PdbId | 20 | the PDB's identity, matched by the image's CodeView debug entry |
//! | EntryPoint | 4 | the entry point's MethodDef token, 0 for none |
//! | ReferencedTypeSystemTables | 8 | a bit per type-system table the PDB references |
//! | TypeSystemTableRows | 4 per bit | the row count of each such table, in table order |
//!
//! # Reference
//!
//! The Portable PDB v1.0 format specification, "#Pdb stream".

use strum::IntoEnumIterator;

use crate::{
    metadata::{tables::TableId, token::Token},
    utils::read_le_at,
    ParseFailure, ParseStage, Result,
};

/// The size of the fixed fields before the row counts.
const FIXED_SIZE: usize = 20 + 4 + 8;

/// A parsed `#Pdb` stream.
///
/// Identifies the PDB and the image it describes: the identity a debugger matches against the
/// image's CodeView entry, the entry point, and the row counts of the image's tables that the
/// PDB's columns are sized by ([`TablesHeader::from_pdb`](crate::metadata::streams::TablesHeader::from_pdb)).
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::{pdb::PdbMetadata, tables::TableId};
///
/// let data = std::fs::read("tests/samples/pdb/portable/PdbProbe.pdb")?;
/// let stream = PdbMetadata::read(&data)?.pdb_stream;
/// println!("PDB id {:02X?}", stream.id);
/// println!("{} MethodDef rows", stream.type_system_rows[TableId::MethodDef as usize]);
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbStream {
    /// The PDB's identity: the GUID and stamp the image's CodeView debug entry names
    pub id: [u8; 20],
    /// The entry point's MethodDef token, `None` for a library
    pub entry_point: Option<Token>,
    /// A bit per type-system table the PDB's tables reference, by [`TableId`]
    pub referenced_tables: u64,
    /// The row count of each type-system table, by [`TableId`]: 0 for a table the PDB does
    /// not reference
    pub type_system_rows: [u32; 64],
}

impl PdbStream {
    /// Reads a `#Pdb` stream.
    ///
    /// # Arguments
    ///
    /// * `data` - The stream's bytes, as the metadata root's stream header bounds them
    ///
    /// # Returns
    ///
    /// The parsed stream; an EntryPoint of 0 reads as `None`, and the row count of a table
    /// the mask does not name as 0.
    ///
    /// # Errors
    ///
    /// When the stream ends before its row counts do, or its mask names a table that is not
    /// a type-system table (a PDB table, or none at all).
    pub fn from(data: &[u8]) -> Result<PdbStream> {
        let truncated = |expected: usize| ParseFailure::Truncated {
            stage: ParseStage::PdbStream,
            expected,
            found: data.len(),
        };
        let id: [u8; 20] = data
            .get(..20)
            .and_then(|id| id.try_into().ok())
            .ok_or_else(|| truncated(FIXED_SIZE))?;
        let mut offset = 20;
        let entry_point = read_le_at::<u32>(data, &mut offset)?;
        let referenced_tables = read_le_at::<u64>(data, &mut offset)?;

        let type_system = TableId::iter()
            .filter(|table| (*table as u8) < TableId::Document as u8)
            .fold(0u64, |mask, table| mask | 1 << (table as u8));
        let foreign = referenced_tables & !type_system;
        if foreign != 0 {
            return Err(ParseFailure::InvalidField {
                stage: ParseStage::PdbStream,
                field: "ReferencedTypeSystemTables",
                reason: format!("names tables that are not type-system tables: 0x{foreign:016X}"),
            }
            .into());
        }

        let mut type_system_rows = [0u32; 64];
        for (index, rows) in type_system_rows.iter_mut().enumerate() {
            if referenced_tables & (1 << index) != 0 {
                *rows = read_le_at::<u32>(data, &mut offset).map_err(|_| {
                    truncated(
                        FIXED_SIZE.saturating_add(referenced_tables.count_ones() as usize * 4),
                    )
                })?;
            }
        }

        Ok(PdbStream {
            id,
            entry_point: (entry_point != 0).then(|| Token::new(entry_point)),
            referenced_tables,
            type_system_rows,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stream of `id`, `entry` and the `(table, rows)` it references.
    fn stream(entry: u32, rows: &[(TableId, u32)]) -> Vec<u8> {
        let mut data: Vec<u8> = (1..=20).collect();
        data.extend_from_slice(&entry.to_le_bytes());
        let mask = rows
            .iter()
            .fold(0u64, |mask, (table, _)| mask | 1 << (*table as u8));
        data.extend_from_slice(&mask.to_le_bytes());
        let mut sorted = rows.to_vec();
        sorted.sort_by_key(|(table, _)| *table as u8);
        for (_, count) in sorted {
            data.extend_from_slice(&count.to_le_bytes());
        }
        data
    }

    /// The row counts land on their tables, in table order whatever order they were listed.
    #[test]
    fn row_counts_land_on_their_tables() {
        let data = stream(
            0x0600_0003,
            &[
                (TableId::MethodDef, 70_000),
                (TableId::TypeDef, 12),
                (TableId::Field, 4),
            ],
        );
        let pdb = PdbStream::from(&data).unwrap();
        assert_eq!(
            pdb.id,
            *b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
        );
        assert_eq!(pdb.entry_point, Some(Token::new(0x0600_0003)));
        assert_eq!(pdb.type_system_rows[TableId::TypeDef as usize], 12);
        assert_eq!(pdb.type_system_rows[TableId::Field as usize], 4);
        assert_eq!(pdb.type_system_rows[TableId::MethodDef as usize], 70_000);
        assert_eq!(pdb.type_system_rows[TableId::Param as usize], 0);
    }

    /// A library has no entry point.
    #[test]
    fn entry_point_zero_is_none() {
        let pdb = PdbStream::from(&stream(0, &[])).unwrap();
        assert_eq!(pdb.entry_point, None);
        assert_eq!(pdb.referenced_tables, 0);
    }

    /// A mask naming a PDB table, or no table, is refused; a stream cut before its counts is.
    #[test]
    fn malformed_streams_are_refused() {
        let mut data = stream(0, &[]);
        data[24..32].copy_from_slice(&(1u64 << TableId::Document as u8).to_le_bytes());
        assert!(PdbStream::from(&data).is_err());
        data[24..32].copy_from_slice(&(1u64 << 0x3F).to_le_bytes());
        assert!(PdbStream::from(&data).is_err());

        let cut = stream(0, &[(TableId::TypeDef, 1)]);
        assert!(PdbStream::from(&cut[..cut.len() - 1]).is_err());
        assert!(PdbStream::from(&cut[..10]).is_err());
    }
}

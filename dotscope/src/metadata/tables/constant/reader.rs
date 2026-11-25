use crate::{
    metadata::{
        tables::{CodedIndex, CodedIndexType, ConstantRaw, RowReadable, TableId, TableInfoRef},
        token::Token,
    },
    utils::{read_le_at, read_le_at_dyn},
    Result,
};

impl RowReadable for ConstantRaw {
    const TABLE_ID: TableId = TableId::Constant;

    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        let offset_org = *offset;

        let c_type = read_le_at::<u8>(data, offset)?;
        let padding = read_le_at::<u8>(data, offset)?;

        Ok(ConstantRaw {
            rid,
            token: Token::new(0x0B00_0000u32.saturating_add(rid)),
            offset: offset_org,
            base: c_type,
            padding,
            parent: CodedIndex::read(data, offset, sizes, CodedIndexType::HasConstant)?,
            value: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, // type
            0x00, // padding
            0x02, 0x02, // parent
            0x03, 0x03, // value
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Property, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<ConstantRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ConstantRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0B000001);
            assert_eq!(row.base, 0x01);
            assert_eq!(
                row.parent,
                CodedIndex::new(TableId::Property, 128, CodedIndexType::HasConstant)
            );
            assert_eq!(row.value, 0x303);
        };

        {
            for row in table.iter() {
                let row = row.expect("row parses");
                eval(row);
            }
        }

        {
            let row = table.get(1).unwrap().unwrap();
            eval(row);
        }
    }

    #[test]
    fn crafted_long() {
        let data = vec![
            0x01, // type
            0x00, // padding
            0x02, 0x02, 0x02, 0x02, // parent
            0x03, 0x03, 0x03, 0x03, // value
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Property, u16::MAX as u32 + 3)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<ConstantRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ConstantRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0B000001);
            assert_eq!(row.base, 0x1);
            assert_eq!(
                row.parent,
                CodedIndex::new(TableId::Property, 0x808080, CodedIndexType::HasConstant)
            );
            assert_eq!(row.value, 0x3030303);
        };

        {
            for row in table.iter() {
                let row = row.expect("row parses");
                eval(row);
            }
        }

        {
            let row = table.get(1).unwrap().unwrap();
            eval(row);
        }
    }
}

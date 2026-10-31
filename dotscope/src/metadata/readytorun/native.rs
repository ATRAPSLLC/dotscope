//! NativeFormat numbers and arrays, the encoding of a ReadyToRun image's own
//! tables (the runtime's `NativeFormat::NativeReader` and `NativeArray`).
//!
//! A NativeFormat array is a header stating the element count, an index of
//! blocks of sixteen elements, and for each block a small binary tree whose
//! leaves are the elements. Every offset in it is relative to a position in
//! its section, so an array reads from the section's bytes alone.

use crate::{Error, Result};

/// The elements a NativeFormat array indexes per block.
const BLOCK_SIZE: u32 = 16;

/// A reader of NativeFormat-encoded numbers and arrays over one section.
pub(crate) struct NativeReader<'a>(pub(crate) &'a [u8]);

impl NativeReader<'_> {
    /// Decodes the unsigned number at `offset` (`NativeReader::DecodeUnsigned`).
    /// Returns the number and the offset past it.
    ///
    /// The count of the first byte's low set bits says how many bytes follow
    /// it: none to three hold the number little-endian above those tag bits,
    /// and four hold a whole `u32` after a tag byte. Five set bits encode
    /// nothing.
    pub(crate) fn unsigned(&self, offset: usize) -> Result<(u32, usize)> {
        let first = *self.0.get(offset).ok_or_else(|| self.overrun(offset))?;
        let width = first.trailing_ones() as usize + 1;
        if width > 5 {
            return Err(malformed_error!(
                "ReadyToRun NativeFormat number at {offset:#x}: no encoding starts {first:#04x}"
            ));
        }
        let end = offset
            .checked_add(width)
            .ok_or_else(|| self.overrun(offset))?;
        let bytes = self
            .0
            .get(offset..end)
            .ok_or_else(|| self.overrun(offset))?;
        let value = match bytes.get(1..) {
            Some(&[b0, b1, b2, b3]) => u32::from_le_bytes([b0, b1, b2, b3]),
            _ => {
                bytes
                    .iter()
                    .rev()
                    .fold(0u32, |value, &byte| (value << 8) | u32::from(byte))
                    >> width
            }
        };
        Ok((value, end))
    }

    /// Reads every element of the array at the start of the section: for
    /// each element present, its index and the offset of its value. An index
    /// with no element is absent.
    ///
    /// # Errors
    ///
    /// When an offset of the array leaves the section or a number is not one
    /// NativeFormat encodes.
    pub(crate) fn array(&self) -> Result<Vec<(u32, usize)>> {
        let (header, base) = self.unsigned(0)?;
        let count = header >> 2;
        // The block index's entries are one, two or four bytes wide.
        let index_width = match header & 3 {
            0 => 1,
            1 => 2,
            2 => 4,
            _ => {
                return Err(malformed_error!(
                    "ReadyToRun NativeFormat array: the block index states no width"
                ));
            }
        };
        let mut elements = Vec::new();
        for index in 0..count {
            if let Some(offset) = self.element(base, index_width, index)? {
                elements.push((index, offset));
            }
        }
        Ok(elements)
    }

    /// The offset of element `index` of the array whose block index starts at
    /// `base` with entries `index_width` bytes wide, or `None` when the array
    /// holds no element there (`NativeArray::TryGetAt`).
    fn element(&self, base: usize, index_width: usize, index: u32) -> Result<Option<usize>> {
        let at = ((index / BLOCK_SIZE) as usize)
            .checked_mul(index_width)
            .and_then(|at| at.checked_add(base))
            .ok_or_else(|| self.overrun(base))?;
        let block = match index_width {
            1 => self.0.get(at).map(|&byte| u32::from(byte)),
            2 => read_u16(self.0, at).map(u32::from),
            _ => read_u32(self.0, at),
        }
        .ok_or_else(|| self.overrun(at))?;
        let mut offset = base
            .checked_add(block as usize)
            .ok_or_else(|| self.overrun(base))?;
        let mut bit = BLOCK_SIZE >> 1;
        while bit > 0 {
            let (node, next) = self.unsigned(offset)?;
            if index & bit != 0 {
                if node & 2 != 0 {
                    offset = offset
                        .checked_add((node >> 2) as usize)
                        .ok_or_else(|| self.overrun(offset))?;
                    bit >>= 1;
                    continue;
                }
            } else if node & 1 != 0 {
                offset = next;
                bit >>= 1;
                continue;
            }
            // Neither child is on the path: a leaf ends the walk early when it
            // is this element's.
            return Ok((node & 3 == 0 && node >> 2 == index % BLOCK_SIZE).then_some(next));
        }
        Ok(Some(offset))
    }

    /// The error of a read past the section's end at `offset`.
    fn overrun(&self, offset: usize) -> Error {
        malformed_error!(
            "ReadyToRun NativeFormat read at {offset:#x} overruns its {:#x}-byte section",
            self.0.len()
        )
    }
}

/// The little-endian `u16` at `bytes[at..]`.
pub(crate) fn read_u16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

/// The little-endian `u32` at `bytes[at..]`.
pub(crate) fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A NativeFormat number reads in each of its five widths**, the width
    /// stated by the first byte's low bits.
    #[test]
    fn a_native_number_reads_in_each_width() {
        let reader = NativeReader(&[
            0x0a, // 5, one byte
            0x05, 0x01, // 0b01 | 1 << 2 | 1 << 8: (1) | (1 << 6) = 65
            0x03, 0x00, 0x01, // three bytes: 1 << 13
            0x07, 0x00, 0x00, 0x01, // four bytes: 1 << 20
            0x0f, 0x78, 0x56, 0x34, 0x12, // five bytes: the next u32
            0x1f, // no encoding
        ]);
        assert_eq!(reader.unsigned(0).unwrap(), (5, 1));
        assert_eq!(reader.unsigned(1).unwrap(), (65, 3));
        assert_eq!(reader.unsigned(3).unwrap(), (1 << 13, 6));
        assert_eq!(reader.unsigned(6).unwrap(), (1 << 20, 10));
        assert_eq!(reader.unsigned(10).unwrap(), (0x1234_5678, 15));
        assert!(reader.unsigned(15).is_err());
        assert!(reader.unsigned(16).is_err(), "past the end");
    }
}

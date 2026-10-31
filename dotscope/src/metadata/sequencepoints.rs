//!
//! Sequence Points parsing and access for PortablePDB MethodDebugInformation.
//!
//! This module provides types and functions to parse and expose sequence points from the
//! PortablePDB format, mapping IL offsets to source code locations for debugging purposes.
//!
//! # Architecture
//!
//! Sequence points are stored in the [`crate::metadata::tables::MethodDebugInformation`] table as a compressed blob.
//! This module parses the blob and exposes a user-friendly API for accessing sequence point data.
//!
//! # Key Components
//!
//! - [`crate::metadata::sequencepoints::SequencePoint`] - Represents a single mapping from IL offset to source code location.
//! - [`crate::metadata::sequencepoints::SequencePoints`] - Collection of sequence points for a method.
//! - [`crate::metadata::sequencepoints::parse_sequence_points`] - Parses a sequence points blob into a collection.
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::sequencepoints::parse_sequence_points;
//!
//! // No local signature; IL offset 1 covers line 10, columns 2 to 7, in
//! // document 1, the method's own.
//! let blob: &[u8] = &[0, 1, 0, 5, 10, 2];
//! let points = parse_sequence_points(blob, 1)?;
//! assert_eq!(points.points.len(), 1);
//! assert_eq!(points.points[0].end_col, 7);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! Returns [`crate::Error`] if the blob is malformed or contains invalid compressed data.
//!
//! # Thread Safety
//!
//! All types in this module are [`Send`] and [`Sync`] because they contain only owned data.
//!
//! # Integration
//!
//! This module integrates with:
//! - Method debug information tables - for exposing parsed sequence points per method
//! - [`crate::file::parser::Parser`] - for binary parsing utilities
//!
//! # Sequence Points Blob Format
//!
//! The blob is laid out as the Portable PDB specification defines it:
//!
//! ```text
//! Blob ::= header SequencePointRecord (SequencePointRecord | document-record)*
//! header ::= LocalSignature InitialDocument?
//! ```
//!
//! - **LocalSignature** (unsigned): the StandAloneSig row of the method's locals, 0 for none.
//! - **InitialDocument** (unsigned): the Document row of the first point; present only when
//!   the method's `MethodDebugInformation.Document` is nil, because its points span documents.
//!
//! A sequence point record is:
//!
//! - **δILOffset** (unsigned): the IL offset for the first record, the non-zero distance from
//!   the previous record's offset after it.
//! - **ΔLines** (unsigned): `EndLine - StartLine`.
//! - **ΔColumns**: `EndColumn - StartColumn`, unsigned and non-zero when ΔLines is 0, signed
//!   otherwise.
//! - **δStartLine**, **δStartColumn**: absolute (unsigned) for the first point that is not
//!   hidden, signed distances from the previous such point after it.
//!
//! A hidden point (lines 0xFEEFEE, columns 0) is a record of only δILOffset, ΔLines = 0 and
//! ΔColumns = 0. A document record, δILOffset = 0 followed by a Document row, switches the
//! document of the points after it.
//!
//! Signed values use the ECMA-335 compressed signed integer encoding (II.23.2).
//!
//! ## References
//!
//! - [PortablePDB Spec](https://github.com/dotnet/runtime/blob/main/docs/design/specs/PortablePdb-Metadata.md#sequence-points-blob)

use crate::{
    file::parser::Parser,
    utils::{write_compressed_int, write_compressed_uint},
    Result,
};

/// The magic line number that indicates a hidden sequence point.
/// This value (0xFEEFEE) is used by .NET compilers to mark compiler-generated
/// or non-user code that should not be shown in debuggers.
pub const HIDDEN_SEQUENCE_POINT_LINE: u32 = 0x00FE_EFEE;

/// Represents a single sequence point mapping IL offset to source code location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequencePoint {
    /// Offset in the method's IL stream.
    pub il_offset: u32,
    /// Starting line in the source file.
    pub start_line: u32,
    /// Starting column in the source file.
    pub start_col: u16,
    /// Ending line in the source file.
    pub end_line: u32,
    /// Ending column in the source file.
    pub end_col: u16,
    /// True if this is a hidden sequence point (start_line == 0xFEEFEE).
    pub is_hidden: bool,
    /// The Document row of the source file, or 0 for the method's own document
    /// (`MethodDebugInformation.Document`).
    pub document: u32,
}

impl SequencePoint {
    /// Creates a new sequence point with validation.
    ///
    /// This constructor validates that the source code range is valid and automatically
    /// computes the `is_hidden` flag based on the start line. The point is in the method's
    /// own document; set [`document`](Self::document) for a method spanning several.
    ///
    /// # Arguments
    ///
    /// * `il_offset` - Offset in the method's IL stream
    /// * `start_line` - Starting line in the source file (1-based, or 0xFEEFEE for hidden)
    /// * `start_col` - Starting column in the source file (1-based)
    /// * `end_line` - Ending line in the source file (must be >= start_line for non-hidden)
    /// * `end_col` - Ending column in the source file
    ///
    /// # Returns
    ///
    /// Returns `Some(SequencePoint)` if the parameters are valid, `None` otherwise.
    ///
    /// # Validation Rules
    ///
    /// For non-hidden sequence points:
    /// - `end_line` must be greater than or equal to `start_line`
    /// - When `end_line == start_line`, `end_col` must be greater than `start_col`: a span of
    ///   no columns on one line is how the format spells a hidden point
    ///
    /// Hidden sequence points (start_line == 0xFEEFEE) bypass range validation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::sequencepoints::SequencePoint;
    ///
    /// // Valid sequence point
    /// let sp = SequencePoint::new(0, 10, 5, 10, 15);
    /// assert!(sp.is_some());
    /// assert!(!sp.unwrap().is_hidden);
    ///
    /// // Invalid: end_col < start_col on same line
    /// let invalid = SequencePoint::new(0, 10, 15, 10, 5);
    /// assert!(invalid.is_none());
    ///
    /// // Hidden sequence point (no range validation)
    /// let hidden = SequencePoint::new(0, 0xFEEFEE, 0, 0xFEEFEE, 0);
    /// assert!(hidden.is_some());
    /// assert!(hidden.unwrap().is_hidden);
    /// ```
    #[must_use]
    pub fn new(
        il_offset: u32,
        start_line: u32,
        start_col: u16,
        end_line: u32,
        end_col: u16,
    ) -> Option<Self> {
        let is_hidden = start_line == HIDDEN_SEQUENCE_POINT_LINE;

        // Validate source range for non-hidden sequence points
        if !is_hidden {
            // End line must be >= start line
            if end_line < start_line {
                return None;
            }
            // On one line, the span must cover at least one column
            if end_line == start_line && end_col <= start_col {
                return None;
            }
        }

        Some(Self {
            il_offset,
            start_line,
            start_col,
            end_line,
            end_col,
            is_hidden,
            document: 0,
        })
    }

    /// Creates a hidden sequence point at the given IL offset.
    ///
    /// Hidden sequence points are used to mark compiler-generated code that should
    /// not be displayed in debuggers. They use the special line number 0xFEEFEE.
    ///
    /// # Arguments
    ///
    /// * `il_offset` - Offset in the method's IL stream
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::sequencepoints::{SequencePoint, HIDDEN_SEQUENCE_POINT_LINE};
    ///
    /// let hidden = SequencePoint::hidden(42);
    /// assert!(hidden.is_hidden);
    /// assert_eq!(hidden.il_offset, 42);
    /// assert_eq!(hidden.start_line, HIDDEN_SEQUENCE_POINT_LINE);
    /// ```
    #[must_use]
    pub fn hidden(il_offset: u32) -> Self {
        Self {
            il_offset,
            start_line: HIDDEN_SEQUENCE_POINT_LINE,
            start_col: 0,
            end_line: HIDDEN_SEQUENCE_POINT_LINE,
            end_col: 0,
            is_hidden: true,
            document: 0,
        }
    }
}

/// Collection of sequence points for a method.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SequencePoints {
    /// The StandAloneSig row of the method's local signature, 0 for none.
    pub local_signature: u32,
    /// The points, in IL offset order.
    pub points: Vec<SequencePoint>,
}

impl SequencePoints {
    /// Returns the sequence point for a given IL offset, if any.
    ///
    /// The point must start exactly at `il_offset`; [`SequencePoints::find_containing`] gives
    /// the point an instruction inside a statement belongs to.
    #[must_use]
    pub fn find_by_il_offset(&self, il_offset: u32) -> Option<&SequencePoint> {
        self.points.iter().find(|sp| sp.il_offset == il_offset)
    }

    /// Returns the sequence point an IL offset belongs to: the last point at or before it, as
    /// a debugger maps an instruction to its source.
    ///
    /// A point covers the IL from its offset up to the next point's. When the covering point
    /// is hidden ([`SequencePoint::is_hidden`]), the offset has no source location. The blob
    /// stores offsets as increasing deltas, so the points are in strictly increasing IL offset
    /// order and the lookup is a binary search.
    ///
    /// # Arguments
    ///
    /// * `il_offset` - An offset in the method's IL
    ///
    /// # Returns
    ///
    /// The covering point, or `None` for an offset before the first point.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::sequencepoints::{SequencePoint, SequencePoints};
    ///
    /// let points = SequencePoints {
    ///     local_signature: 0,
    ///     points: vec![
    ///         SequencePoint::new(0, 10, 5, 10, 20).unwrap(),
    ///         SequencePoint::new(6, 11, 5, 11, 30).unwrap(),
    ///     ],
    /// };
    /// assert_eq!(points.find_containing(4).unwrap().start_line, 10);
    /// assert_eq!(points.find_containing(6).unwrap().start_line, 11);
    /// assert_eq!(points.find_containing(100).unwrap().start_line, 11);
    /// ```
    #[must_use]
    pub fn find_containing(&self, il_offset: u32) -> Option<&SequencePoint> {
        let after = self
            .points
            .partition_point(|point| point.il_offset <= il_offset);
        after
            .checked_sub(1)
            .and_then(|index| self.points.get(index))
    }

    /// Serializes the sequence points to the Portable PDB blob format.
    ///
    /// # Arguments
    ///
    /// * `document` - The method's `MethodDebugInformation.Document` row, or 0 when its points
    ///   span several documents; a point whose own `document` is 0 is in this one.
    ///
    /// # Format
    ///
    /// See the [module documentation](self#sequence-points-blob-format).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::metadata::sequencepoints::{SequencePoint, SequencePoints};
    /// let points = SequencePoints {
    ///     local_signature: 0,
    ///     points: vec![SequencePoint::new(1, 10, 2, 10, 7).unwrap()],
    /// };
    /// let bytes = points.to_bytes(1)?;
    /// // local signature, IL offset, ΔLines, ΔColumns, start line, start column
    /// assert_eq!(bytes, vec![0, 1, 0, 5, 10, 2]);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error when the points cannot be encoded: offsets not strictly
    /// increasing, a range that ends before it starts or covers no column on one
    /// line, a point with no document when the method has none, a point in another
    /// document than a method with one, or a delta outside the range of a
    /// compressed signed integer.
    pub fn to_bytes(&self, document: u32) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        write_compressed_uint(self.local_signature, &mut buffer)?;

        let document_of = |point: &SequencePoint| -> Result<u32> {
            match (point.document, document) {
                (0, 0) => Err(malformed_error!(
                    "sequence point at IL_{:04x} has no document, and neither has its method",
                    point.il_offset
                )),
                (0, method) => Ok(method),
                (own, 0) => Ok(own),
                (own, method) if own == method => Ok(own),
                (own, method) => Err(malformed_error!(
                    "sequence point at IL_{:04x} is in document {own}, outside its method's {method}",
                    point.il_offset
                )),
            }
        };

        let mut current_document = match self.points.first() {
            Some(first) if document == 0 => {
                let initial = document_of(first)?;
                write_compressed_uint(initial, &mut buffer)?;
                initial
            }
            _ => document,
        };

        let mut previous_offset: Option<u32> = None;
        let mut previous_start: Option<(u32, u16)> = None;
        for point in &self.points {
            let point_document = document_of(point)?;
            if point_document != current_document {
                // A document record: δILOffset 0, then the row.
                write_compressed_uint(0, &mut buffer)?;
                write_compressed_uint(point_document, &mut buffer)?;
                current_document = point_document;
            }

            let offset_delta = match previous_offset {
                None => point.il_offset,
                Some(previous) => match point.il_offset.checked_sub(previous) {
                    Some(delta) if delta > 0 => delta,
                    _ => {
                        return Err(malformed_error!(
                            "sequence point at IL_{:04x} does not follow IL_{previous:04x}",
                            point.il_offset
                        ))
                    }
                },
            };
            write_compressed_uint(offset_delta, &mut buffer)?;
            previous_offset = Some(point.il_offset);

            if point.is_hidden {
                write_compressed_uint(0, &mut buffer)?;
                write_compressed_uint(0, &mut buffer)?;
                continue;
            }

            let line_delta = point
                .end_line
                .checked_sub(point.start_line)
                .ok_or_else(|| {
                    malformed_error!(
                        "sequence point at IL_{:04x} ends on line {} before it starts on {}",
                        point.il_offset,
                        point.end_line,
                        point.start_line
                    )
                })?;
            write_compressed_uint(line_delta, &mut buffer)?;
            let column_delta = i32::from(point.end_col).saturating_sub(i32::from(point.start_col));
            if line_delta == 0 {
                let columns = u32::try_from(column_delta)
                    .ok()
                    .filter(|&columns| columns > 0)
                    .ok_or_else(|| {
                        malformed_error!(
                            "sequence point at IL_{:04x} covers no column of line {}",
                            point.il_offset,
                            point.start_line
                        )
                    })?;
                write_compressed_uint(columns, &mut buffer)?;
            } else {
                write_compressed_int(column_delta, &mut buffer)?;
            }

            match previous_start {
                None => {
                    write_compressed_uint(point.start_line, &mut buffer)?;
                    write_compressed_uint(u32::from(point.start_col), &mut buffer)?;
                }
                Some((line, col)) => {
                    let line_step = i64::from(point.start_line).saturating_sub(i64::from(line));
                    let line_step = i32::try_from(line_step).map_err(|_| {
                        malformed_error!(
                            "sequence point at IL_{:04x} is {line_step} lines from the last",
                            point.il_offset
                        )
                    })?;
                    write_compressed_int(line_step, &mut buffer)?;
                    write_compressed_int(
                        i32::from(point.start_col).saturating_sub(i32::from(col)),
                        &mut buffer,
                    )?;
                }
            }
            previous_start = Some((point.start_line, point.start_col));
        }

        Ok(buffer)
    }
}

/// Parses a PortablePDB sequence points blob into a SequencePoints collection.
///
/// # Arguments
/// * `blob` - The raw sequence points blob from MethodDebugInformation.
/// * `document` - The `MethodDebugInformation.Document` row, or 0 when the method's points
///   span several documents and the blob names the first one.
///
/// # Returns
/// * `Ok(SequencePoints)` on success, every point carrying the Document row it is in.
///
/// # Errors
///
/// Returns an error when the blob is truncated, a record breaks the format (a zero
/// offset step outside a document record, a line or column outside its range), or
/// a value overflows.
pub fn parse_sequence_points(blob: &[u8], document: u32) -> Result<SequencePoints> {
    let mut parser = Parser::new(blob);
    if !parser.has_more_data() {
        return Ok(SequencePoints::default());
    }

    let local_signature = parser.read_compressed_uint()?;
    let mut current_document = if document == 0 {
        parser.read_compressed_uint()?
    } else {
        document
    };

    let mut points = Vec::new();
    let mut il_offset: Option<u32> = None;
    let mut previous_start: Option<(u32, u16)> = None;
    while parser.has_more_data() {
        let offset_delta = parser.read_compressed_uint()?;
        if offset_delta == 0 && il_offset.is_some() {
            // A document record.
            current_document = parser.read_compressed_uint()?;
            continue;
        }
        let offset = match il_offset {
            None => offset_delta,
            Some(previous) => previous
                .checked_add(offset_delta)
                .ok_or_else(|| malformed_error!("IL offset overflow in sequence points"))?,
        };
        il_offset = Some(offset);

        let line_delta = parser.read_compressed_uint()?;
        let column_delta = if line_delta == 0 {
            i64::from(parser.read_compressed_uint()?)
        } else {
            i64::from(parser.read_compressed_int()?)
        };

        if line_delta == 0 && column_delta == 0 {
            let mut point = SequencePoint::hidden(offset);
            point.document = current_document;
            points.push(point);
            continue;
        }

        let (start_line, start_col) = match previous_start {
            None => (
                i64::from(parser.read_compressed_uint()?),
                i64::from(parser.read_compressed_uint()?),
            ),
            Some((line, col)) => (
                i64::from(line).saturating_add(i64::from(parser.read_compressed_int()?)),
                i64::from(col).saturating_add(i64::from(parser.read_compressed_int()?)),
            ),
        };
        let start_line = u32::try_from(start_line)
            .map_err(|_| malformed_error!("sequence point start line {start_line} out of range"))?;
        let start_col = u16::try_from(start_col).map_err(|_| {
            malformed_error!("sequence point start column {start_col} out of range")
        })?;
        let end_line = start_line
            .checked_add(line_delta)
            .ok_or_else(|| malformed_error!("End line overflow in sequence points"))?;
        let end_col = u16::try_from(i64::from(start_col).saturating_add(column_delta))
            .map_err(|_| malformed_error!("End column out of range in sequence points"))?;
        previous_start = Some((start_line, start_col));

        points.push(SequencePoint {
            il_offset: offset,
            start_line,
            start_col,
            end_line,
            end_col,
            is_hidden: false,
            document: current_document,
        });
    }
    Ok(SequencePoints {
        local_signature,
        points,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(il_offset: u32, start: (u32, u16), end: (u32, u16)) -> SequencePoint {
        SequencePoint::new(il_offset, start.0, start.1, end.0, end.1).unwrap()
    }

    /// An offset belongs to the last point at or before it; a hidden point hides the IL it
    /// covers, and an offset before the first point has none.
    #[test]
    fn an_offset_belongs_to_the_point_covering_it() {
        let points = SequencePoints {
            local_signature: 0,
            points: vec![
                point(2, (10, 5), (10, 20)),
                SequencePoint::hidden(8),
                point(12, (11, 5), (11, 30)),
            ],
        };
        assert!(points.find_containing(1).is_none());
        assert_eq!(points.find_containing(2).unwrap().start_line, 10);
        assert_eq!(points.find_containing(7).unwrap().start_line, 10);
        assert!(points.find_containing(9).unwrap().is_hidden);
        assert_eq!(points.find_containing(500).unwrap().start_line, 11);
        assert!(points.find_by_il_offset(7).is_none());
    }

    #[test]
    fn parse_empty_blob() {
        let result = parse_sequence_points(&[], 1).unwrap();
        assert!(result.points.is_empty());
        assert_eq!(result.local_signature, 0);
    }

    #[test]
    fn parse_single_sequence_point() {
        // LocalSignature 0x11, IL 1, ΔLines 0, ΔColumns 5, line 10, column 2.
        let blob: &[u8] = &[0x11, 1, 0, 5, 10, 2];
        let result = parse_sequence_points(blob, 3).unwrap();
        assert_eq!(result.local_signature, 0x11);
        assert_eq!(result.points.len(), 1);
        let sp = &result.points[0];
        assert_eq!(sp.il_offset, 1);
        assert_eq!(sp.start_line, 10);
        assert_eq!(sp.start_col, 2);
        assert_eq!(sp.end_line, 10);
        assert_eq!(sp.end_col, 7);
        assert_eq!(sp.document, 3);
        assert!(!sp.is_hidden);
    }

    #[test]
    fn parse_hidden_sequence_point() {
        // A hidden record is δILOffset, ΔLines 0, ΔColumns 0 and nothing else;
        // the point after it takes its start line absolutely, as the first
        // point that is not hidden.
        let blob: &[u8] = &[0, 0, 0, 0, 4, 0, 3, 12, 1];
        let result = parse_sequence_points(blob, 1).unwrap();
        assert_eq!(result.points.len(), 2);
        let hidden = &result.points[0];
        assert!(hidden.is_hidden);
        assert_eq!(hidden.il_offset, 0);
        assert_eq!(hidden.start_line, HIDDEN_SEQUENCE_POINT_LINE);
        let next = &result.points[1];
        assert_eq!(next.il_offset, 4);
        assert_eq!((next.start_line, next.start_col), (12, 1));
        assert_eq!((next.end_line, next.end_col), (12, 4));
    }

    #[test]
    fn parse_deltas_relative_to_the_last_visible_point() {
        // Line 10 col 2..7 at IL 1; hidden at IL 3; line 9 col 4 to line 11
        // col 1 at IL 6: ΔLines 2, ΔColumns -3 signed (0x7B), δStartLine -1
        // (0x7F) and δStartColumn +2 (0x04), both from the point at IL 1.
        let blob: &[u8] = &[0, 1, 0, 5, 10, 2, 2, 0, 0, 3, 2, 0x7B, 0x7F, 0x04];
        let result = parse_sequence_points(blob, 1).unwrap();
        assert_eq!(result.points.len(), 3);
        assert!(result.points[1].is_hidden);
        let last = &result.points[2];
        assert_eq!(last.il_offset, 6);
        assert_eq!((last.start_line, last.start_col), (9, 4));
        assert_eq!((last.end_line, last.end_col), (11, 1));
    }

    #[test]
    fn parse_document_records() {
        // A method spanning documents: InitialDocument 2, a point, a
        // document record switching to 5, a point.
        let blob: &[u8] = &[0, 2, 0, 0, 1, 1, 1, 0, 5, 3, 0, 1, 0x02, 0x00];
        let result = parse_sequence_points(blob, 0).unwrap();
        assert_eq!(result.points.len(), 2);
        assert_eq!(result.points[0].document, 2);
        assert_eq!(result.points[1].document, 5);
        assert_eq!(result.points[1].il_offset, 3);
        assert_eq!(result.points[1].start_line, 2);
    }

    #[test]
    fn encoding_roundtrips() {
        let mut far = point(40, (300, 1), (300, 9));
        far.document = 7;
        let points = SequencePoints {
            local_signature: 0x0102,
            points: vec![
                point(0, (10, 5), (10, 20)),
                SequencePoint::hidden(2),
                point(6, (9, 30), (12, 2)),
                point(20, (100, 1), (100, 2)),
                far,
            ],
        };
        let refused = points.to_bytes(0).unwrap_err();
        assert!(refused.to_string().contains("no document"), "{refused}");

        let mut in_documents = points.clone();
        for point in &mut in_documents.points {
            if point.document == 0 {
                point.document = 3;
            }
        }
        let bytes = in_documents.to_bytes(0).unwrap();
        assert_eq!(parse_sequence_points(&bytes, 0).unwrap(), in_documents);
    }

    #[test]
    fn encoding_refuses_what_the_format_cannot_hold() {
        let unordered = SequencePoints {
            local_signature: 0,
            points: vec![point(4, (1, 1), (1, 2)), point(4, (2, 1), (2, 2))],
        };
        assert!(unordered.to_bytes(1).is_err());

        let mut empty_span = point(0, (1, 1), (1, 2));
        empty_span.end_col = 1;
        let empty = SequencePoints {
            local_signature: 0,
            points: vec![empty_span],
        };
        assert!(empty.to_bytes(1).is_err());

        let mut elsewhere = point(0, (1, 1), (1, 2));
        elsewhere.document = 2;
        let foreign = SequencePoints {
            local_signature: 0,
            points: vec![elsewhere],
        };
        assert!(foreign.to_bytes(1).is_err());
    }

    // Tests for SequencePoint::new constructor

    #[test]
    fn new_valid_single_line_sequence_point() {
        let sp = SequencePoint::new(0, 10, 5, 10, 15);
        assert!(sp.is_some());
        let sp = sp.unwrap();
        assert_eq!(sp.il_offset, 0);
        assert_eq!(sp.start_line, 10);
        assert_eq!(sp.start_col, 5);
        assert_eq!(sp.end_line, 10);
        assert_eq!(sp.end_col, 15);
        assert!(!sp.is_hidden);
        assert_eq!(sp.document, 0);
    }

    #[test]
    fn new_valid_multi_line_sequence_point() {
        let sp = SequencePoint::new(42, 10, 5, 15, 3);
        assert!(sp.is_some());
        let sp = sp.unwrap();
        assert_eq!(sp.il_offset, 42);
        assert_eq!(sp.start_line, 10);
        assert_eq!(sp.start_col, 5);
        assert_eq!(sp.end_line, 15);
        assert_eq!(sp.end_col, 3);
        assert!(!sp.is_hidden);
    }

    #[test]
    fn new_invalid_end_line_before_start() {
        let sp = SequencePoint::new(0, 10, 5, 5, 15);
        assert!(sp.is_none(), "Should reject end_line < start_line");
    }

    #[test]
    fn new_invalid_end_col_before_start_same_line() {
        let sp = SequencePoint::new(0, 10, 15, 10, 5);
        assert!(
            sp.is_none(),
            "Should reject end_col < start_col on same line"
        );
    }

    #[test]
    fn new_invalid_empty_span_on_one_line() {
        // Zero columns on one line is the hidden point's encoding.
        assert!(SequencePoint::new(0, 10, 5, 10, 5).is_none());
    }

    #[test]
    fn new_hidden_sequence_point() {
        let sp = SequencePoint::new(
            0,
            HIDDEN_SEQUENCE_POINT_LINE,
            0,
            HIDDEN_SEQUENCE_POINT_LINE,
            0,
        );
        assert!(sp.is_some());
        let sp = sp.unwrap();
        assert!(sp.is_hidden);
        assert_eq!(sp.start_line, HIDDEN_SEQUENCE_POINT_LINE);
    }

    #[test]
    fn hidden_constructor() {
        let sp = SequencePoint::hidden(42);
        assert!(sp.is_hidden);
        assert_eq!(sp.il_offset, 42);
        assert_eq!(sp.start_line, HIDDEN_SEQUENCE_POINT_LINE);
        assert_eq!(sp.start_col, 0);
        assert_eq!(sp.end_line, HIDDEN_SEQUENCE_POINT_LINE);
        assert_eq!(sp.end_col, 0);
    }
}

//! Custom debug information blob decoding and encoding for the Portable PDB
//! `CustomDebugInformation` table.
//!
//! A CustomDebugInformation row's value is a blob whose layout its kind (a GUID) decides.
//! This module reads each kind's blob into a [`CustomDebugInfo`] and writes a value back to
//! the bytes it came from, so a blob read and written again is unchanged.
//!
//! # Architecture
//!
//! [`parse_custom_debug_blob`] dispatches on the [`CustomDebugKind`] and reads the blob with
//! a bounds-checked [`Parser`]: every count and offset is checked against the bytes left, a
//! blob that ends inside a value or has bytes after it is refused, and text that the format
//! defines as UTF-8 must be UTF-8. A kind dotscope does not know keeps its bytes as they are.
//! [`encode_custom_debug_blob`] is its inverse, writing the canonical form the C# and Visual
//! Basic compilers write (the same baselines and the same compressed integer widths). The
//! [module documentation](crate::metadata::customdebuginformation) gives each kind's layout.
//!
//! An embedded source is not inflated while it is read: the value keeps the stored bytes, and
//! [`CustomDebugInfo::embedded_source_bytes`] and [`CustomDebugInfo::embedded_source_text`]
//! inflate it on request, no further than the size the blob states. Loading an assembly
//! therefore never allocates for embedded sources beyond the blob itself.
//!
//! # Key Components
//!
//! - [`parse_custom_debug_blob`] - decodes a blob of a kind into a [`CustomDebugInfo`]
//! - [`encode_custom_debug_blob`] - writes a value back to the blob it decodes from
//! - [`CustomDebugInfo::embedded_source_bytes`] and
//!   [`CustomDebugInfo::embedded_source_text`] - an embedded source, inflated on request
//!
//! # Usage Examples
//!
//! ## Reading and writing a blob
//!
//! ```rust
//! use dotscope::metadata::customdebuginformation::{
//!     encode_custom_debug_blob, parse_custom_debug_blob, CustomDebugInfo, CustomDebugKind,
//! };
//!
//! // `(string first, string second)` written by the C# compiler
//! let blob = b"first\0second\0";
//! let info = parse_custom_debug_blob(blob, CustomDebugKind::TupleElementNames)?;
//! assert_eq!(
//!     info,
//!     CustomDebugInfo::TupleElementNames(vec![
//!         Some("first".to_string()),
//!         Some("second".to_string()),
//!     ])
//! );
//! assert_eq!(encode_custom_debug_blob(&info)?, blob);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Reading an embedded source
//!
//! ```rust
//! use dotscope::metadata::customdebuginformation::{parse_custom_debug_blob, CustomDebugKind};
//!
//! // Format 0: the source as it is, here with a UTF-8 byte order mark
//! let mut blob = 0i32.to_le_bytes().to_vec();
//! blob.extend_from_slice(b"\xEF\xBB\xBFclass Program { }");
//! let info = parse_custom_debug_blob(&blob, CustomDebugKind::EmbeddedSource)?;
//! assert_eq!(info.embedded_source_text().unwrap()?, "class Program { }");
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! Decoding returns [`crate::Error::Malformed`] when a blob is not in its kind's format: it
//! ends inside a value, a count or offset is out of range, it has bytes after its value, or
//! text the format defines as UTF-8 is not. Encoding fails when a value cannot be written in
//! its format, such as text holding the NUL that ends it or a count past a compressed
//! integer's range.
//!
//! # Performance Considerations
//!
//! Decoding allocates only the value itself: lists are sized from the blob where the format
//! gives a count, text is copied once, and an embedded source keeps its stored bytes rather
//! than inflating them. Inflating happens on each call to the embedded source accessors and
//! is bounded by the size the blob states, so a hostile blob cannot make a load allocate more
//! than the blob's own size, nor an accessor more than the size it declares.
//!
//! # Thread Safety
//!
//! The functions are stateless and the values own their data, so both can be used from any
//! number of threads at once.
//!
//! # Integration
//!
//! - [`crate::metadata::tables::CustomDebugInformation`] - the table rows decode their Value
//!   blob with [`parse_custom_debug_blob`] when they are loaded
//! - [`crate::metadata::pdb::PortablePdb`] - an assembly's rows, looked up by parent
//! - [`crate::file::parser::Parser`] - the bounds-checked reader the decoder uses
//!
//! # Standards Compliance
//!
//! - **Portable PDB**: the layouts of the specification's records, and of the compilers'
//!   records it does not describe as Roslyn writes them
//! - **ECMA-335**: compressed integers (II.23.2) for counts, offsets and rows
//! - **Round trip**: every blob the C# and Visual Basic compilers wrote for the probe
//!   assemblies decodes and encodes back to its bytes (the module's tests)
//!
//! # References
//!
//! - The Portable PDB v1.0 format specification, "Language Specific Custom Debug Information
//!   Records"
//! - For the kinds the specification does not describe (EncStateMachineStateMap,
//!   TupleElementNames, AsyncMethodSteppingInformation, PrimaryConstructorInformation): the
//!   C# and Visual Basic compilers' writers (Roslyn's `MetadataWriter.PortablePdb` and
//!   `EditAndContinueMethodDebugInformation`)

use std::io::Read;

use uguid::Guid;

use crate::{
    file::parser::Parser,
    metadata::customdebuginformation::types::{
        AsyncAwait, CustomDebugInfo, CustomDebugKind, EncLambda, EncLocalSlot,
        EncStateMachineState, HoistedLocalScope, MetadataReferenceInfo,
    },
    utils::{write_compressed_int, write_compressed_uint},
    Result,
};

/// The byte that opens an Edit and Continue local slot map's syntax offset baseline.
const SYNTAX_OFFSET_BASELINE: u8 = 0xFF;

/// Decodes a custom debug information blob of `kind`.
///
/// The blob must hold exactly one value in its kind's format (the
/// [module documentation](crate::metadata::customdebuginformation) gives each layout); a kind
/// dotscope does not know decodes to [`CustomDebugInfo::Unknown`] with the blob as it is.
///
/// # Arguments
///
/// * `data` - The blob, as the row's Value column names it in the `#Blob` heap
/// * `kind` - The row's kind, from its Kind column's GUID ([`CustomDebugKind::from_guid`])
///
/// # Returns
///
/// The decoded value, of the variant `kind` names.
///
/// # Errors
///
/// Returns [`crate::Error::Malformed`] when the blob is not in its kind's format: it ends
/// inside a value, a count or offset is out of range, bytes follow the value, or text the
/// format defines as UTF-8 is not.
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::customdebuginformation::{
///     parse_custom_debug_blob, CustomDebugInfo, CustomDebugKind,
/// };
///
/// let info = parse_custom_debug_blob(b"{\"documents\":{}}", CustomDebugKind::SourceLink)?;
/// assert_eq!(info, CustomDebugInfo::SourceLink("{\"documents\":{}}".to_string()));
///
/// // Hoisted local scopes are 8 bytes each
/// assert!(parse_custom_debug_blob(&[0; 5], CustomDebugKind::StateMachineHoistedLocalScopes)
///     .is_err());
/// # Ok::<(), dotscope::Error>(())
/// ```
pub fn parse_custom_debug_blob(data: &[u8], kind: CustomDebugKind) -> Result<CustomDebugInfo> {
    let mut parser = Parser::new(data);
    let info = match kind {
        CustomDebugKind::StateMachineHoistedLocalScopes => {
            if !data.len().is_multiple_of(8) {
                return Err(malformed_error!(
                    "hoisted local scopes are 8 bytes each, not {} in all",
                    data.len()
                ));
            }
            let mut scopes = Vec::with_capacity(data.len() / 8);
            while parser.has_more_data() {
                scopes.push(HoistedLocalScope {
                    start: parser.read_le::<u32>()?,
                    length: parser.read_le::<u32>()?,
                });
            }
            CustomDebugInfo::StateMachineHoistedLocalScopes(scopes)
        }
        CustomDebugKind::DynamicLocalVariables => {
            return Ok(CustomDebugInfo::DynamicLocalVariables(data.to_vec()))
        }
        CustomDebugKind::DefaultNamespace => {
            return Ok(CustomDebugInfo::DefaultNamespace(utf8(data)?))
        }
        CustomDebugKind::EncLocalSlotMap => {
            let mut baseline = -1i32;
            if parser.peek_byte().ok() == Some(SYNTAX_OFFSET_BASELINE) {
                parser.advance()?;
                baseline = negated(parser.read_compressed_uint()?)?;
            }
            let mut slots = Vec::new();
            while parser.has_more_data() {
                let byte = parser.read_le::<u8>()?;
                if byte == 0 {
                    slots.push(None);
                    continue;
                }
                let syntax_offset = offset(parser.read_compressed_uint()?, baseline)?;
                let ordinal = if byte & 0x80 != 0 {
                    Some(parser.read_compressed_uint()?)
                } else {
                    None
                };
                slots.push(Some(EncLocalSlot {
                    kind: byte & 0x7F,
                    syntax_offset,
                    ordinal,
                }));
            }
            CustomDebugInfo::EncLocalSlotMap(slots)
        }
        CustomDebugKind::EncLambdaAndClosureMap => {
            let method_ordinal = i32::try_from(parser.read_compressed_uint()?)
                .map_err(|_| malformed_error!("a method ordinal past 2^31"))?
                .saturating_sub(1);
            let baseline = negated(parser.read_compressed_uint()?)?;
            let count = parser.read_compressed_uint()?;
            let mut closures = Vec::new();
            for _ in 0..count {
                closures.push(offset(parser.read_compressed_uint()?, baseline)?);
            }
            let mut lambdas = Vec::new();
            while parser.has_more_data() {
                lambdas.push(EncLambda {
                    syntax_offset: offset(parser.read_compressed_uint()?, baseline)?,
                    closure: parser.read_compressed_uint()?,
                });
            }
            CustomDebugInfo::EncLambdaAndClosureMap {
                method_ordinal,
                closures,
                lambdas,
            }
        }
        CustomDebugKind::EncStateMachineStateMap => {
            let count = parser.read_compressed_uint()?;
            let mut states = Vec::new();
            if count > 0 {
                let baseline = negated(parser.read_compressed_uint()?)?;
                for _ in 0..count {
                    states.push(EncStateMachineState {
                        state: parser.read_compressed_int()?,
                        syntax_offset: offset(parser.read_compressed_uint()?, baseline)?,
                    });
                }
            }
            CustomDebugInfo::EncStateMachineStateMap(states)
        }
        CustomDebugKind::EmbeddedSource => {
            return Ok(CustomDebugInfo::EmbeddedSource {
                format: parser.read_le::<i32>()?,
                content: data.get(4..).unwrap_or_default().to_vec(),
            })
        }
        CustomDebugKind::SourceLink => return Ok(CustomDebugInfo::SourceLink(utf8(data)?)),
        CustomDebugKind::CompilationMetadataReferences => {
            let mut references = Vec::new();
            while parser.has_more_data() {
                let file_name = nul_terminated(&mut parser, data)?;
                let aliases = nul_terminated(&mut parser, data)?;
                references.push(MetadataReferenceInfo {
                    file_name,
                    aliases: if aliases.is_empty() {
                        Vec::new()
                    } else {
                        aliases.split(',').map(str::to_string).collect()
                    },
                    flags: parser.read_le::<u8>()?,
                    timestamp: parser.read_le::<u32>()?,
                    image_size: parser.read_le::<u32>()?,
                    mvid: guid(&mut parser)?,
                });
            }
            CustomDebugInfo::CompilationMetadataReferences(references)
        }
        CustomDebugKind::CompilationOptions => {
            let mut options = Vec::new();
            while parser.has_more_data() {
                let name = nul_terminated(&mut parser, data)?;
                let value = nul_terminated(&mut parser, data)?;
                options.push((name, value));
            }
            CustomDebugInfo::CompilationOptions(options)
        }
        CustomDebugKind::TupleElementNames => {
            let mut names = Vec::new();
            while parser.has_more_data() {
                let name = nul_terminated(&mut parser, data)?;
                names.push((!name.is_empty()).then_some(name));
            }
            CustomDebugInfo::TupleElementNames(names)
        }
        CustomDebugKind::TypeDefinitionDocuments => {
            let mut documents = Vec::new();
            while parser.has_more_data() {
                documents.push(parser.read_compressed_uint()?);
            }
            CustomDebugInfo::TypeDefinitionDocuments(documents)
        }
        CustomDebugKind::AsyncMethodSteppingInformation => {
            let catch_handler = parser.read_le::<u32>()?.checked_sub(1);
            let mut awaits = Vec::new();
            while parser.has_more_data() {
                awaits.push(AsyncAwait {
                    yield_offset: parser.read_le::<u32>()?,
                    resume_offset: parser.read_le::<u32>()?,
                    method: parser.read_compressed_uint()?,
                });
            }
            CustomDebugInfo::AsyncMethodSteppingInformation {
                catch_handler,
                awaits,
            }
        }
        CustomDebugKind::PrimaryConstructorInformation => {
            CustomDebugInfo::PrimaryConstructorInformation
        }
        CustomDebugKind::Unknown(kind) => {
            return Ok(CustomDebugInfo::Unknown {
                kind,
                data: data.to_vec(),
            })
        }
    };
    if parser.has_more_data() {
        return Err(malformed_error!(
            "a {kind:?} blob has {} bytes after its value",
            data.len().saturating_sub(parser.pos())
        ));
    }
    Ok(info)
}

/// Encodes a custom debug information value in its kind's format.
///
/// The inverse of [`parse_custom_debug_blob`]: the bytes are those the C# and Visual Basic
/// compilers write for the value (the same syntax offset baselines, the smallest compressed
/// integer encodings), so a blob they wrote decodes and encodes back to itself.
///
/// # Arguments
///
/// * `info` - The value to encode; its variant decides the format
///
/// # Returns
///
/// The blob, for a row whose kind is [`CustomDebugInfo::kind`].
///
/// # Errors
///
/// Returns [`crate::Error::Malformed`] when the value cannot be written in its format: a
/// count, ordinal or syntax offset outside what a compressed integer holds, a catch handler
/// offset of `u32::MAX`, or text holding the NUL that the format ends it with.
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::customdebuginformation::{
///     encode_custom_debug_blob, CustomDebugInfo, HoistedLocalScope,
/// };
///
/// let scopes = CustomDebugInfo::StateMachineHoistedLocalScopes(vec![HoistedLocalScope {
///     start: 0x20,
///     length: 0x57,
/// }]);
/// assert_eq!(
///     encode_custom_debug_blob(&scopes)?,
///     [0x20, 0, 0, 0, 0x57, 0, 0, 0]
/// );
/// # Ok::<(), dotscope::Error>(())
/// ```
pub fn encode_custom_debug_blob(info: &CustomDebugInfo) -> Result<Vec<u8>> {
    let mut blob = Vec::new();
    match info {
        CustomDebugInfo::StateMachineHoistedLocalScopes(scopes) => {
            for scope in scopes {
                blob.extend_from_slice(&scope.start.to_le_bytes());
                blob.extend_from_slice(&scope.length.to_le_bytes());
            }
        }
        CustomDebugInfo::DynamicLocalVariables(bits) => blob.extend_from_slice(bits),
        CustomDebugInfo::DefaultNamespace(text) | CustomDebugInfo::SourceLink(text) => {
            blob.extend_from_slice(text.as_bytes());
        }
        CustomDebugInfo::EncLocalSlotMap(slots) => {
            let baseline = slots
                .iter()
                .flatten()
                .map(|slot| slot.syntax_offset)
                .fold(-1, i32::min);
            if baseline != -1 {
                blob.push(SYNTAX_OFFSET_BASELINE);
                write_compressed_uint(baseline.unsigned_abs(), &mut blob)?;
            }
            for slot in slots {
                match slot {
                    None => blob.push(0),
                    Some(slot) => {
                        blob.push(slot.kind & 0x7F | if slot.ordinal.is_some() { 0x80 } else { 0 });
                        write_compressed_uint(relative(slot.syntax_offset, baseline)?, &mut blob)?;
                        if let Some(ordinal) = slot.ordinal {
                            write_compressed_uint(ordinal, &mut blob)?;
                        }
                    }
                }
            }
        }
        CustomDebugInfo::EncLambdaAndClosureMap {
            method_ordinal,
            closures,
            lambdas,
        } => {
            let baseline = closures
                .iter()
                .copied()
                .chain(lambdas.iter().map(|lambda| lambda.syntax_offset))
                .fold(-1, i32::min);
            write_compressed_uint(
                u32::try_from(method_ordinal.saturating_add(1))
                    .map_err(|_| malformed_error!("a method ordinal below -1"))?,
                &mut blob,
            )?;
            write_compressed_uint(baseline.unsigned_abs(), &mut blob)?;
            write_compressed_uint(count(closures.len())?, &mut blob)?;
            for closure in closures {
                write_compressed_uint(relative(*closure, baseline)?, &mut blob)?;
            }
            for lambda in lambdas {
                write_compressed_uint(relative(lambda.syntax_offset, baseline)?, &mut blob)?;
                write_compressed_uint(lambda.closure, &mut blob)?;
            }
        }
        CustomDebugInfo::EncStateMachineStateMap(states) => {
            write_compressed_uint(count(states.len())?, &mut blob)?;
            if !states.is_empty() {
                let baseline = states
                    .iter()
                    .map(|state| state.syntax_offset)
                    .fold(0, i32::min);
                write_compressed_uint(baseline.unsigned_abs(), &mut blob)?;
                for state in states {
                    write_compressed_int(state.state, &mut blob)?;
                    write_compressed_uint(relative(state.syntax_offset, baseline)?, &mut blob)?;
                }
            }
        }
        CustomDebugInfo::EmbeddedSource { format, content } => {
            blob.extend_from_slice(&format.to_le_bytes());
            blob.extend_from_slice(content);
        }
        CustomDebugInfo::CompilationMetadataReferences(references) => {
            for reference in references {
                write_nul_terminated(&reference.file_name, &mut blob)?;
                write_nul_terminated(&reference.aliases.join(","), &mut blob)?;
                blob.push(reference.flags);
                blob.extend_from_slice(&reference.timestamp.to_le_bytes());
                blob.extend_from_slice(&reference.image_size.to_le_bytes());
                blob.extend_from_slice(&reference.mvid.to_bytes());
            }
        }
        CustomDebugInfo::CompilationOptions(options) => {
            for (name, value) in options {
                write_nul_terminated(name, &mut blob)?;
                write_nul_terminated(value, &mut blob)?;
            }
        }
        CustomDebugInfo::TupleElementNames(names) => {
            for name in names {
                write_nul_terminated(name.as_deref().unwrap_or_default(), &mut blob)?;
            }
        }
        CustomDebugInfo::TypeDefinitionDocuments(documents) => {
            for document in documents {
                write_compressed_uint(*document, &mut blob)?;
            }
        }
        CustomDebugInfo::AsyncMethodSteppingInformation {
            catch_handler,
            awaits,
        } => {
            let catch = match catch_handler {
                Some(offset) => offset
                    .checked_add(1)
                    .ok_or_else(|| malformed_error!("a catch handler offset of 2^32 - 1"))?,
                None => 0,
            };
            blob.extend_from_slice(&catch.to_le_bytes());
            for await_point in awaits {
                blob.extend_from_slice(&await_point.yield_offset.to_le_bytes());
                blob.extend_from_slice(&await_point.resume_offset.to_le_bytes());
                write_compressed_uint(await_point.method, &mut blob)?;
            }
        }
        CustomDebugInfo::PrimaryConstructorInformation => {}
        CustomDebugInfo::Unknown { data, .. } => blob.extend_from_slice(data),
    }
    Ok(blob)
}

impl CustomDebugInfo {
    /// An embedded source's bytes, inflated when it is stored deflated.
    ///
    /// A source stored as it is (`format` 0) is returned unchanged. A deflated one is inflated
    /// no further than the size its `format` states (plus one byte, to tell a longer stream
    /// from an exact one), so a blob cannot make this allocate more than it declares.
    ///
    /// # Returns
    ///
    /// `None` for a value of any other kind; otherwise the source's bytes, or the reason
    /// they cannot be read.
    ///
    /// # Errors
    ///
    /// The inner result is [`crate::Error::Malformed`] when the format is negative
    /// (reserved), the content is not a deflate stream, or it inflates to more or fewer bytes
    /// than the format states.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::customdebuginformation::CustomDebugInfo;
    ///
    /// let stored = CustomDebugInfo::EmbeddedSource {
    ///     format: 0,
    ///     content: b"class A { }".to_vec(),
    /// };
    /// assert_eq!(stored.embedded_source_bytes().unwrap()?, b"class A { }");
    ///
    /// // A size the content does not inflate to is refused
    /// let short = CustomDebugInfo::EmbeddedSource {
    ///     format: 64,
    ///     content: vec![0x03, 0x00],
    /// };
    /// assert!(short.embedded_source_bytes().unwrap().is_err());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn embedded_source_bytes(&self) -> Option<Result<Vec<u8>>> {
        let CustomDebugInfo::EmbeddedSource { format, content } = self else {
            return None;
        };
        Some(match *format {
            0 => Ok(content.clone()),
            size if size > 0 => {
                let size = size.unsigned_abs();
                let mut source = Vec::new();
                match flate2::read::DeflateDecoder::new(content.as_slice())
                    .take(u64::from(size).saturating_add(1))
                    .read_to_end(&mut source)
                {
                    Ok(_) if source.len() == size as usize => Ok(source),
                    Ok(_) if source.len() > size as usize => Err(malformed_error!(
                        "an embedded source states {size} bytes and inflates to more"
                    )),
                    Ok(_) => Err(malformed_error!(
                        "an embedded source states {size} bytes and inflates to {}",
                        source.len()
                    )),
                    Err(e) => Err(malformed_error!("an embedded source does not inflate: {e}")),
                }
            }
            reserved => Err(malformed_error!(
                "an embedded source's format {reserved} is reserved"
            )),
        })
    }

    /// An embedded source's text.
    ///
    /// The bytes ([`CustomDebugInfo::embedded_source_bytes`]) are decoded by their byte order
    /// mark, as the compilers and debuggers do: UTF-8, UTF-16 little-endian or UTF-16
    /// big-endian, and UTF-8 when there is none. The mark is not part of the text, and an
    /// invalid sequence reads as U+FFFD rather than failing, since the source is for display.
    ///
    /// # Returns
    ///
    /// `None` for a value of any other kind; otherwise the text, or the reason the bytes
    /// cannot be read.
    ///
    /// # Errors
    ///
    /// As [`CustomDebugInfo::embedded_source_bytes`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::customdebuginformation::CustomDebugInfo;
    ///
    /// // UTF-16 little-endian, with its byte order mark
    /// let source = CustomDebugInfo::EmbeddedSource {
    ///     format: 0,
    ///     content: vec![0xFF, 0xFE, b'h', 0, b'i', 0],
    /// };
    /// assert_eq!(source.embedded_source_text().unwrap()?, "hi");
    /// assert!(CustomDebugInfo::SourceLink(String::new()).embedded_source_text().is_none());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn embedded_source_text(&self) -> Option<Result<String>> {
        self.embedded_source_bytes().map(|bytes| {
            let bytes = bytes?;
            Ok(match bytes.as_slice() {
                [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
                [0xFF, 0xFE, rest @ ..] => utf16(rest, u16::from_le_bytes),
                [0xFE, 0xFF, rest @ ..] => utf16(rest, u16::from_be_bytes),
                other => String::from_utf8_lossy(other).into_owned(),
            })
        })
    }
}

/// UTF-16 text in the byte order `unit` reads.
fn utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&pair| unit(pair))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Text that must be UTF-8.
fn utf8(data: &[u8]) -> Result<String> {
    String::from_utf8(data.to_vec()).map_err(|e| malformed_error!("text that is not UTF-8: {e}"))
}

/// UTF-8 text up to the NUL that ends it.
fn nul_terminated(parser: &mut Parser<'_>, data: &[u8]) -> Result<String> {
    let start = parser.pos();
    let rest = data.get(start..).unwrap_or_default();
    let length = rest
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(|| malformed_error!("text with no NUL to end it"))?;
    let text = utf8(rest.get(..length).unwrap_or_default())?;
    parser.seek(start.saturating_add(length).saturating_add(1))?;
    Ok(text)
}

/// Writes `text` and the NUL that ends it.
fn write_nul_terminated(text: &str, blob: &mut Vec<u8>) -> Result<()> {
    if text.contains('\0') {
        return Err(malformed_error!(
            "text ends at a NUL, and {text:?} holds one"
        ));
    }
    blob.extend_from_slice(text.as_bytes());
    blob.push(0);
    Ok(())
}

/// A GUID's 16 bytes.
fn guid(parser: &mut Parser<'_>) -> Result<Guid> {
    let mut bytes = [0u8; 16];
    for byte in &mut bytes {
        *byte = parser.read_le::<u8>()?;
    }
    Ok(Guid::from_bytes(bytes))
}

/// A syntax offset baseline as stored: negated.
fn negated(stored: u32) -> Result<i32> {
    i32::try_from(stored)
        .map(i32::wrapping_neg)
        .map_err(|_| malformed_error!("a syntax offset baseline past 2^31"))
}

/// A syntax offset: the stored value plus the baseline.
fn offset(stored: u32, baseline: i32) -> Result<i32> {
    i32::try_from(stored)
        .ok()
        .and_then(|stored| stored.checked_add(baseline))
        .ok_or_else(|| malformed_error!("a syntax offset past 2^31"))
}

/// A syntax offset as stored: less the baseline.
fn relative(syntax_offset: i32, baseline: i32) -> Result<u32> {
    syntax_offset
        .checked_sub(baseline)
        .and_then(|relative| u32::try_from(relative).ok())
        .ok_or_else(|| malformed_error!("a syntax offset below its baseline"))
}

/// A count as a compressed integer can hold it.
fn count(length: usize) -> Result<u32> {
    u32::try_from(length).map_err(|_| malformed_error!("a count past 2^32"))
}

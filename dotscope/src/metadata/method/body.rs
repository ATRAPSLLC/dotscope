//! Representation and parsing of CIL method bodies in .NET assemblies.
//!
//! This module provides types and logic for decoding method headers, CIL bytecode, local variable
//! signatures, and exception handling regions from .NET metadata. Supports both tiny and fat method
//! headers as specified by ECMA-335.
//!
//! # Method Body Format
//!
//! .NET methods can have two types of headers:
//!
//! ## Tiny Headers
//! - **Size**: 1 byte
//! - **Code Size**: Up to 63 bytes
//! - **Max Stack**: Fixed at 8
//! - **Local Variables**: None allowed
//! - **Exception Handling**: Not supported
//! - **Use Case**: Simple methods with minimal bytecode
//!
//! ## Fat Headers
//! - **Size**: 12 bytes minimum
//! - **Code Size**: Up to 4GB
//! - **Max Stack**: Configurable up to 65535
//! - **Local Variables**: Supported with signature token
//! - **Exception Handling**: Full support with multiple handlers
//! - **Use Case**: Complex methods with significant bytecode
//!
//! # Exception Handling
//!
//! Fat method headers can include exception handling sections with:
//! - **Try Blocks**: Protected code regions
//! - **Handler Types**: Exception, finally, fault, and filter handlers
//! - **Multiple Handlers**: Support for nested and sequential exception handling
//! - **Section Formats**: Both tiny (12-byte) and fat (24-byte) handler entries
//!
//! # Thread Safety
//!
//! All types in this module are thread-safe:
//! - **`MethodBody`**: Immutable after construction
//! - **Parsing**: No shared state during parsing operations
//! - **Exception Handlers**: Read-only data structures
//!
//! # Usage Patterns
//!
//! ## Basic Method Information
//! ```no_run
//! use dotscope::metadata::method::MethodBody;
//!
//! let method_data = /* ... method body bytes ... */;
//! let body = MethodBody::from(method_data)?;
//!
//! println!("Method has {} bytes of IL code", body.size_code);
//! println!("Header type: {}", if body.is_fat { "Fat" } else { "Tiny" });
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Local Variable Analysis
//! ```no_run
//! if body.local_var_sig_token != 0 {
//!     println!("Method has local variables (signature token: 0x{:08X})",
//!              body.local_var_sig_token);
//!     if body.is_init_local {
//!         println!("Local variables are zero-initialized");
//!     }
//! }
//! ```
//!
//! ## Exception Handler Processing
//! ```no_run
//! if body.is_exception_data {
//!     println!("Method has {} exception handlers", body.exception_handlers.len());
//!     for (i, handler) in body.exception_handlers.iter().enumerate() {
//!         println!("Handler {}: try=[{:#x}..{:#x}], handler=[{:#x}..{:#x}]",
//!                  i, handler.try_offset,
//!                  handler.try_offset + handler.try_length,
//!                  handler.handler_offset,
//!                  handler.handler_offset + handler.handler_length);
//!     }
//! }
//! ```
//!
//! # Examples
//!
//! ```rust,no_run
//! use dotscope::{CilObject, metadata::method::MethodBody};
//!
//! let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
//! let methods = assembly.methods();
//!
//! for entry in methods.iter() {
//!     let (token, method) = (entry.key(), entry.value());
//!     if let Some(body) = method.body.get() {
//!         println!("Method {}: {} bytes of IL code", method.name, body.size_code);
//!         println!("  Max stack: {}", body.max_stack);
//!         println!("  Header type: {}", if body.is_fat { "Fat" } else { "Tiny" });
//!         if body.local_var_sig_token != 0 {
//!             println!("  Has local variables (token: 0x{:08X})", body.local_var_sig_token);
//!         }
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # References
//! - ECMA-335 6th Edition, Partition II, Section 25.4 - Method Header Format
//! - ECMA-335 6th Edition, Partition II, Section 25.4.6 - Exception Handling Data Sections

use std::io::Write;

use log::debug;

use crate::{
    metadata::method::{
        encode_exception_handlers, ExceptionHandler, ExceptionHandlerFlags, ExceptionSectionFormat,
        MethodBodyFlags, SectionFlags,
    },
    utils::{read_le, read_le_at},
    Result,
};

/// Controls how exception handler validation is performed during parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EhValidationMode {
    /// Strict: return error on any invalid handler (used by `from()`)
    Strict,
    /// Filter: log warning and skip invalid handlers (used by `from_lenient()`)
    Filter,
    /// Raw: no validation, keep all parsed handlers (used by `from_raw()` for detection)
    Raw,
}

/// Validates that an exception handler's offsets and lengths are within the method body bounds.
///
/// # Arguments
/// * `handler` - The exception handler to validate
/// * `code_size` - The size of the method's IL code in bytes
/// * `handler_index` - The index of the handler (for error messages)
///
/// # Errors
/// Returns an error if any offset or region extends beyond the method body.
fn validate_exception_handler_bounds(
    handler: &ExceptionHandler,
    code_size: u32,
    handler_index: usize,
) -> Result<()> {
    let try_end = handler
        .try_offset
        .checked_add(handler.try_length)
        .ok_or_else(|| {
            malformed_error!(
                "Exception handler {} try region overflow: offset {} + length {} overflows u32",
                handler_index,
                handler.try_offset,
                handler.try_length
            )
        })?;

    if try_end > code_size {
        return Err(malformed_error!(
            "Exception handler {} try region [{}, {}) exceeds method code size {}",
            handler_index,
            handler.try_offset,
            try_end,
            code_size
        ));
    }

    let handler_end = handler
        .handler_offset
        .checked_add(handler.handler_length)
        .ok_or_else(|| {
            malformed_error!(
                "Exception handler {} handler region overflow: offset {} + length {} overflows u32",
                handler_index,
                handler.handler_offset,
                handler.handler_length
            )
        })?;

    if handler_end > code_size {
        return Err(malformed_error!(
            "Exception handler {} handler region [{}, {}) exceeds method code size {}",
            handler_index,
            handler.handler_offset,
            handler_end,
            code_size
        ));
    }

    if handler.flags.contains(ExceptionHandlerFlags::FILTER) && handler.filter_offset >= code_size {
        return Err(malformed_error!(
            "Exception handler {} filter offset {} exceeds method code size {}",
            handler_index,
            handler.filter_offset,
            code_size
        ));
    }

    Ok(())
}

/// Describes one method that has been compiled to CIL bytecode.
///
/// The `MethodBody` struct represents the parsed body of a .NET method, including header information,
/// code size, stack requirements, local variable signature, and exception handling regions.
///
/// # Header Format Detection
///
/// The structure automatically detects whether the method uses a tiny or fat header format
/// based on the first byte(s) of the method body data:
/// - **Tiny Format**: Single byte header for methods with ≤63 bytes of code
/// - **Fat Format**: 12-byte header for complex methods with extensive metadata
///
/// # Field Organization
///
/// ## Size Information
/// - [`Self::size_code`]: Length of the actual CIL instructions in bytes
/// - [`Self::size_header`]: Length of the method header (1 for tiny, 12+ for fat)
///
/// ## Stack and Variables
/// - [`Self::max_stack`]: Maximum operand stack depth during execution
/// - [`Self::local_var_sig_token`]: Metadata token for local variable type signature
/// - [`Self::is_init_local`]: Whether local variables are zero-initialized
///
/// ## Format and Features
/// - [`Self::is_fat`]: Whether this method uses the fat header format
/// - [`Self::is_exception_data`]: Whether exception handling data is present
/// - [`Self::exception_handlers`]: Collection of exception handling regions
///
/// # Memory Layout
///
/// ```text
/// Tiny Header (1 byte):
/// ┌─────────────────────────────────────┐
/// │ Size(6) │ Reserved(2) │ Format(2)   │
/// └─────────────────────────────────────┘
///
/// Fat Header (12 bytes):
/// ┌─────────────────────────────────────┐
/// │ Flags(12) │ Size(4) │ Format(2)     │  (bytes 0-1)
/// ├─────────────────────────────────────┤
/// │ MaxStack (16 bits)                  │  (bytes 2-3)
/// ├─────────────────────────────────────┤
/// │ CodeSize (32 bits)                  │  (bytes 4-7)
/// ├─────────────────────────────────────┤
/// │ LocalVarSigTok (32 bits)            │  (bytes 8-11)
/// └─────────────────────────────────────┘
/// ```
///
/// # Thread Safety
///
/// `MethodBody` is fully thread-safe:
/// - All fields are immutable after construction
/// - No interior mutability or shared state
/// - Safe to share across threads without synchronization
#[derive(Debug, Clone)]
pub struct MethodBody {
    /// Size of the method code (length of all CIL instructions, excluding the header) in bytes
    pub size_code: usize,
    /// Size of the method header in bytes (1 for tiny format, 12+ for fat format)
    pub size_header: usize,
    /// Metadata token for a signature describing the layout of local variables (0 = no locals)
    pub local_var_sig_token: u32,
    /// Maximum number of items on the operand stack during method execution
    pub max_stack: usize,
    /// Flag indicating the method header format (false = tiny, true = fat)
    pub is_fat: bool,
    /// Flag indicating whether to zero-initialize all local variables before method execution
    pub is_init_local: bool,
    /// Flag indicating whether this method has exception handling data sections
    pub is_exception_data: bool,
    /// Collection of exception handlers for this method (empty if no exception handling)
    pub exception_handlers: Vec<ExceptionHandler>,
    /// How the exception handling section was written, for a body read with one: writing
    /// the body uses it, so the section comes back as it was.
    pub exception_format: Option<ExceptionSectionFormat>,
}

impl MethodBody {
    /// Create a `MethodBody` object from a sequence of bytes.
    ///
    /// Parses a complete .NET method body including header, CIL instructions, and optional
    /// exception handling sections. Automatically detects and handles both tiny and fat
    /// header formats according to ECMA-335 specifications.
    ///
    /// # Arguments
    ///
    /// * `data` - The byte slice containing the complete method body data, starting with
    ///   the method header and including all CIL instructions and exception handling sections
    ///
    /// # Returns
    ///
    /// * [`Ok`]([`MethodBody`]) - Successfully parsed method body with all metadata
    /// * [`Err`]([`crate::Error`]) - Parsing failed due to invalid format, insufficient data, or corruption
    ///
    /// # Errors
    ///
    /// This method returns an error in the following cases:
    /// - **Empty Data**: The provided byte slice is empty
    /// - **Invalid Format**: Header format bits don't match tiny or fat patterns
    /// - **Insufficient Data**: Not enough bytes for the declared header or code size
    /// - **Malformed Sections**: Exception handling sections have invalid structure
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::method::MethodBody;
    ///
    /// let method_data = &[0x16, 0x00, 0x2A]; // Simple method: ldarg.0, ret
    /// let body = MethodBody::from(method_data)?;
    ///
    /// assert!(!body.is_fat);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn from(data: &[u8]) -> Result<MethodBody> {
        let (body, _) = Self::parse(data, EhValidationMode::Strict)?;
        Ok(body)
    }

    /// Create a `MethodBody` from bytes, filtering out invalid exception handlers.
    ///
    /// This is useful for parsing method bodies with malformed exception handlers
    /// (e.g., injected by BitMono's AntiDecompiler) where the handler offsets are
    /// garbage but the method header and IL code are valid. Invalid handlers are
    /// logged and skipped; only valid handlers are kept.
    ///
    /// # Arguments
    ///
    /// * `data` - The byte slice containing the complete method body data
    ///
    /// # Returns
    ///
    /// * [`Ok`]`((MethodBody, usize))` - Successfully parsed method body with only valid
    ///   exception handlers, and the count of invalid handlers that were filtered out
    /// * [`Err`]([`crate::Error`]) - Parsing failed due to invalid header format or insufficient data
    pub fn from_lenient(data: &[u8]) -> Result<(MethodBody, usize)> {
        let (body, filtered) = Self::parse(data, EhValidationMode::Filter)?;
        if filtered > 0 {
            log::warn!(
                "Filtered {filtered} invalid exception handler(s), {} valid handler(s) kept",
                body.exception_handlers.len()
            );
        }
        Ok((body, filtered))
    }

    /// Parse without any EH validation. Returns all parsed handlers including garbage.
    ///
    /// Used for obfuscation detection where we need to see raw handler data to
    /// identify injected garbage exception handlers.
    ///
    /// # Arguments
    ///
    /// * `data` - The byte slice containing the complete method body data
    ///
    /// # Returns
    ///
    /// * [`Ok`]([`MethodBody`]) - Successfully parsed method body with all handlers (unvalidated)
    /// * [`Err`]([`crate::Error`]) - Parsing failed due to invalid header format or insufficient data
    pub fn from_raw(data: &[u8]) -> Result<MethodBody> {
        let (body, _) = Self::parse(data, EhValidationMode::Raw)?;
        Ok(body)
    }

    /// Validates and pushes a parsed exception handler according to the validation mode.
    ///
    /// - **Strict**: validates bounds and returns error on failure
    /// - **Filter**: validates bounds; valid handlers are pushed, invalid ones increment
    ///   `filtered_count` silently (caller logs the total)
    /// - **Raw**: pushes unconditionally
    fn push_handler(
        handler: ExceptionHandler,
        handler_idx: usize,
        code_size: u32,
        eh_mode: EhValidationMode,
        handlers: &mut Vec<ExceptionHandler>,
        filtered_count: &mut usize,
    ) -> Result<()> {
        match eh_mode {
            EhValidationMode::Strict => {
                validate_exception_handler_bounds(&handler, code_size, handler_idx)?;
                handlers.push(handler);
            }
            EhValidationMode::Filter => {
                if validate_exception_handler_bounds(&handler, code_size, handler_idx).is_ok() {
                    handlers.push(handler);
                } else {
                    *filtered_count = filtered_count
                        .checked_add(1)
                        .ok_or_else(|| malformed_error!("filtered_count overflow"))?;
                }
            }
            EhValidationMode::Raw => {
                handlers.push(handler);
            }
        }
        Ok(())
    }

    /// Internal parsing logic shared by `from()`, `from_lenient()`, and `from_raw()`.
    ///
    /// Returns the parsed body and the number of filtered (invalid) exception handlers.
    /// In Strict mode, this count is always 0 (errors abort before counting).
    /// In Raw mode, this count is always 0 (nothing is filtered).
    fn parse(data: &[u8], eh_mode: EhValidationMode) -> Result<(MethodBody, usize)> {
        if data.is_empty() {
            return Err(malformed_error!("Provided data for body parsing is empty"));
        }

        let first_byte = read_le::<u8>(data)?;
        match MethodBodyFlags::new(u16::from(first_byte & 0b_00000011_u8)) {
            MethodBodyFlags::TINY_FORMAT => {
                let size_code = (first_byte >> 2) as usize;
                let needed = size_code
                    .checked_add(1)
                    .ok_or_else(|| malformed_error!("tiny method body size overflow"))?;
                if needed > data.len() {
                    return Err(out_of_bounds_error!());
                }

                Ok((
                    MethodBody {
                        size_code,
                        size_header: 1,
                        local_var_sig_token: 0,
                        max_stack: 8,
                        is_fat: false,
                        is_init_local: false,
                        is_exception_data: false,
                        exception_handlers: Vec::new(),
                        exception_format: None,
                    },
                    0,
                ))
            }
            MethodBodyFlags::FAT_FORMAT => {
                if data.len() < 12 {
                    return Err(out_of_bounds_error!());
                }

                let first_duo = read_le::<u16>(data)?;

                // ECMA-335 II.25.4.3: the top nibble is the header size in dwords, and the
                // spec mandates 3 (12 bytes).
                //
                // Only a value *below* 3 is actually dangerous: `size_code` is read from
                // offset 4 and `localVarSigTok` from offset 8, so a shorter header would make
                // the body start inside its own header and shift every downstream offset. That
                // is refused.
                //
                // A value above 3 is non-conformant but not ambiguous, and it is what real
                // runtimes accept: CoreCLR and dnlib both locate the IL at
                // `4 * (flags >> 12)` rather than assuming 12. Rejecting those outright would
                // make dotscope refuse assemblies the CLR happily executes - the wrong trade
                // for a malware-analysis tool, whose input is by definition not
                // spec-conformant. The declared size is honoured and the deviation is reported.
                let header_dwords = first_duo >> 12;
                if header_dwords < 3 {
                    return Err(malformed_error!(
                        "fat method header declares {} dwords, ECMA-335 II.25.4.3 requires at least 3",
                        header_dwords
                    ));
                }
                if header_dwords > 3 {
                    debug!(
                        "fat method header declares {header_dwords} dwords; ECMA-335 II.25.4.3 \
                         mandates 3, honouring the declared size as CoreCLR and dnlib do"
                    );
                }

                // Every downstream offset - the IL start, the `size_code` bounds check and the
                // EH cursor - is derived from this, so it must be the declared size rather
                // than a hard-coded 12.
                let size_header: u16 = header_dwords.saturating_mul(4);
                let size_code = read_le::<u32>(data.get(4..).ok_or(out_of_bounds_error!())?)?;
                let total = (size_code as usize)
                    .checked_add(size_header as usize)
                    .ok_or_else(|| malformed_error!("fat method body total size overflow"))?;
                if data.len() < total {
                    return Err(out_of_bounds_error!());
                }

                let local_var_sig_token =
                    read_le::<u32>(data.get(8..).ok_or(out_of_bounds_error!())?)?;
                let flags_header = MethodBodyFlags::new(first_duo & 0b_0000111111111111_u16);
                let max_stack =
                    read_le::<u16>(data.get(2..).ok_or(out_of_bounds_error!())?)? as usize;

                let is_init_local = flags_header.contains(MethodBodyFlags::INIT_LOCALS);

                // The data sections after the code (ECMA-335 II.25.4.5), walked as CoreCLR
                // walks them: each starts 4-aligned after the last, `DataSize` bytes on; a
                // section whose kind is not the EH table is skipped, and the first EH table
                // is the method's handlers, any later one ignored.
                let mut exception_handlers = Vec::new();
                let mut exception_format = None;
                let mut filtered_count: usize = 0;
                let mut more = flags_header.contains(MethodBodyFlags::MORE_SECTS);
                let mut cursor = (size_header as usize)
                    .checked_add(size_code as usize)
                    .and_then(|end| end.checked_next_multiple_of(4))
                    .ok_or_else(|| malformed_error!("EH cursor overflow"))?;
                while more {
                    let Some(header) = data.get(cursor..cursor.saturating_add(4)) else {
                        if eh_mode == EhValidationMode::Strict {
                            return Err(malformed_error!(
                                "A data section header at {} runs past the method body",
                                cursor
                            ));
                        }
                        break;
                    };
                    let kind = SectionFlags::new(header.first().copied().unwrap_or_default());
                    let fat = kind.contains(SectionFlags::FAT_FORMAT);
                    let data_size = if fat {
                        u32::from_le_bytes([
                            header.get(1).copied().unwrap_or_default(),
                            header.get(2).copied().unwrap_or_default(),
                            header.get(3).copied().unwrap_or_default(),
                            0,
                        ])
                    } else {
                        u32::from(header.get(1).copied().unwrap_or_default())
                    };
                    more = kind.contains(SectionFlags::MORE_SECTS);

                    if kind.bits() & SectionFlags::KIND_MASK.bits() == SectionFlags::EHTABLE.bits()
                        && exception_format.is_none()
                    {
                        exception_format = Some(ExceptionSectionFormat { fat, data_size });
                        // The runtime counts DataSize / clause size clauses, so a DataSize that
                        // leaves out the 4-byte header (as AsmResolver writes it) reads the same
                        let clause_size: usize = if fat { 24 } else { 12 };
                        let handler_count = (data_size as usize)
                            .checked_div(clause_size)
                            .unwrap_or_default();
                        let clauses_end = handler_count
                            .checked_mul(clause_size)
                            .and_then(|size| size.checked_add(cursor.saturating_add(4)))
                            .ok_or_else(|| malformed_error!("EH section size overflow"))?;
                        if clauses_end > data.len() {
                            if eh_mode == EhValidationMode::Strict {
                                return Err(malformed_error!(
                                    "An exception section of {} clauses runs past the method body",
                                    handler_count
                                ));
                            }
                            break;
                        }
                        exception_handlers.reserve(handler_count);
                        let mut clause = cursor.saturating_add(4);
                        for handler_idx in 0..handler_count {
                            let handler = if fat {
                                let flags_u32 = read_le_at::<u32>(data, &mut clause)?;
                                if flags_u32 > 0xFFFF && eh_mode == EhValidationMode::Strict {
                                    return Err(malformed_error!(
                                        "Exception handler {} has invalid flags with upper bits set: 0x{:08X}",
                                        handler_idx,
                                        flags_u32
                                    ));
                                }
                                // In Filter/Raw mode, truncate to u16 and let push_handler
                                // validate via bounds checking - garbage flags typically
                                // accompany garbage offsets that will be rejected there.
                                #[allow(clippy::cast_possible_truncation)]
                                let flags = ExceptionHandlerFlags::new(flags_u32 as u16);
                                ExceptionHandler {
                                    flags,
                                    try_offset: read_le_at::<u32>(data, &mut clause)?,
                                    try_length: read_le_at::<u32>(data, &mut clause)?,
                                    handler_offset: read_le_at::<u32>(data, &mut clause)?,
                                    handler_length: read_le_at::<u32>(data, &mut clause)?,
                                    filter_offset: read_le_at::<u32>(data, &mut clause)?,
                                    handler: None,
                                }
                            } else {
                                ExceptionHandler {
                                    flags: ExceptionHandlerFlags::new(read_le_at::<u16>(
                                        data,
                                        &mut clause,
                                    )?),
                                    try_offset: u32::from(read_le_at::<u16>(data, &mut clause)?),
                                    try_length: u32::from(read_le_at::<u8>(data, &mut clause)?),
                                    handler_offset: u32::from(read_le_at::<u16>(
                                        data,
                                        &mut clause,
                                    )?),
                                    handler_length: u32::from(read_le_at::<u8>(data, &mut clause)?),
                                    filter_offset: read_le_at::<u32>(data, &mut clause)?,
                                    handler: None,
                                }
                            };
                            Self::push_handler(
                                handler,
                                handler_idx,
                                size_code,
                                eh_mode,
                                &mut exception_handlers,
                                &mut filtered_count,
                            )?;
                        }
                    }

                    // The next section, 4-aligned after this one's DataSize
                    let next = cursor
                        .checked_add(data_size as usize)
                        .and_then(|end| end.checked_next_multiple_of(4))
                        .ok_or_else(|| malformed_error!("EH section cursor overflow"))?;
                    if next <= cursor {
                        if eh_mode == EhValidationMode::Strict && more {
                            return Err(malformed_error!(
                                "A data section of DataSize {} is followed by another",
                                data_size
                            ));
                        }
                        break;
                    }
                    cursor = next;
                }

                Ok((
                    MethodBody {
                        size_code: size_code as usize,
                        size_header: size_header as usize,
                        local_var_sig_token,
                        max_stack,
                        is_fat: true,
                        is_init_local,
                        is_exception_data: !exception_handlers.is_empty(),
                        exception_handlers,
                        exception_format,
                    },
                    filtered_count,
                ))
            }
            _ => Err(malformed_error!(
                "MethodHeader is neither FAT nor TINY - {}",
                first_byte
            )),
        }
    }

    /// Get the total serialized size including header, code, and exception handlers.
    ///
    /// This calculates the complete size of the method body as it appears in the
    /// assembly file, including:
    /// - Method header (1 byte for tiny, 12 bytes for fat)
    /// - IL code bytes
    /// - 4-byte alignment padding (for fat format with exception handlers)
    /// - Exception handler sections
    ///
    /// # Returns
    ///
    /// The total serialized size in bytes.
    #[must_use]
    pub fn size(&self) -> usize {
        let base_size = self.size_header.saturating_add(self.size_code);

        if self.exception_handlers.is_empty() {
            return base_size;
        }

        // Exception handlers require 4-byte alignment after the code
        let aligned_base = base_size.saturating_add(3) & !3usize;

        // Determine if we need fat or small exception handler format
        let needs_fat_format = self.exception_handlers.iter().any(|h| {
            h.try_offset > 0xFFFF
                || h.try_length > 0xFF
                || h.handler_offset > 0xFFFF
                || h.handler_length > 0xFF
        });

        let per_handler = if needs_fat_format { 24 } else { 12 };
        let section_size = self
            .exception_handlers
            .len()
            .saturating_mul(per_handler)
            .saturating_add(4);

        aligned_base.saturating_add(section_size)
    }

    /// Writes the method body to a writer.
    ///
    /// Serializes the method header (tiny or fat format), IL code, and exception handlers
    /// directly to the provided writer. This avoids intermediate buffers for efficient
    /// streaming output.
    ///
    /// # Arguments
    ///
    /// * `writer` - Any type implementing [`std::io::Write`]
    /// * `il_code` - The IL bytecode for the method
    ///
    /// # Returns
    ///
    /// The total number of bytes written (header + code + exception handlers + padding).
    ///
    /// # Format Selection
    ///
    /// The format is the body's own, [`Self::is_fat`], so a body writes back with the header
    /// it was read with:
    /// - **Tiny Format**: a body that is not fat, while its code is at most 63 bytes, it has
    ///   no local variables, no exception handlers and a maximum stack of at most 8
    /// - **Fat Format**: a fat body, keeping its maximum stack and `InitLocals` flag, and a
    ///   body the tiny format cannot hold
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::method::MethodBody;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let body = MethodBody {
    ///     size_code: 2,
    ///     size_header: 1,
    ///     local_var_sig_token: 0,
    ///     max_stack: 8,
    ///     is_fat: false,
    ///     is_init_local: false,
    ///     is_exception_data: false,
    ///     exception_handlers: vec![],
    /// };
    ///
    /// let il_code = vec![0x17, 0x2A]; // ldc.i4.1, ret
    /// let mut buffer = Vec::new();
    /// let bytes_written = body.write_to(&mut buffer, &il_code)?;
    ///
    /// assert_eq!(bytes_written, 3); // 1-byte header + 2-byte code
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the writer fails or if the method body
    /// parameters are invalid (e.g., code size exceeds limits).
    pub fn write_to<W: Write>(&self, writer: &mut W, il_code: &[u8]) -> Result<u64> {
        let code_size = il_code.len();
        let has_exceptions = !self.exception_handlers.is_empty();

        // The body's own format, unless the tiny one cannot hold it: it has no InitLocals
        // flag, which also zeroes `localloc` memory
        let use_tiny = !self.is_fat
            && code_size <= 63
            && self.max_stack <= 8
            && self.local_var_sig_token == 0
            && !has_exceptions
            && !self.is_init_local;

        let mut bytes_written: u64 = 0;

        if use_tiny {
            // Tiny format: single byte header
            // Bits 7-2: code size (6 bits)
            // Bits 1-0: format (0x02 for tiny)
            let code_size_u8 = u8::try_from(code_size).map_err(|_| {
                malformed_error!("Code size {} exceeds tiny format limit", code_size)
            })?;
            let header_byte = (code_size_u8 << 2) | 0x02;
            writer.write_all(&[header_byte])?;
            bytes_written = bytes_written
                .checked_add(1)
                .ok_or_else(|| malformed_error!("method body byte count overflow"))?;
        } else {
            // Fat format: 12-byte header
            let code_size_u32 = u32::try_from(code_size)
                .map_err(|_| malformed_error!("Code size {} exceeds u32 range", code_size))?;
            let max_stack_u16 = u16::try_from(self.max_stack)
                .map_err(|_| malformed_error!("Max stack {} exceeds u16 range", self.max_stack))?;

            // Flags layout (ECMA-335 II.25.4.4):
            // Bits 0-1: Format (0x03 for fat)
            // Bit 3: CorILMethod_MoreSects (0x08)
            // Bit 4: CorILMethod_InitLocals (0x10)
            // Bits 12-15: Size in dwords (3 for fat header = 12 bytes)
            let mut flags: u16 = 0x3003; // Size (3 << 12) | FAT_FORMAT (0x03)
            if has_exceptions {
                flags |= 0x0008; // MORE_SECTS
            }
            if self.is_init_local {
                flags |= 0x0010; // INIT_LOCALS
            }

            // Write header fields
            writer.write_all(&flags.to_le_bytes())?;
            writer.write_all(&max_stack_u16.to_le_bytes())?;
            writer.write_all(&code_size_u32.to_le_bytes())?;
            writer.write_all(&self.local_var_sig_token.to_le_bytes())?;
            bytes_written = bytes_written
                .checked_add(12)
                .ok_or_else(|| malformed_error!("method body byte count overflow"))?;
        }

        // Write IL code
        writer.write_all(il_code)?;
        bytes_written = bytes_written
            .checked_add(code_size as u64)
            .ok_or_else(|| malformed_error!("method body byte count overflow"))?;

        // Write exception handlers if present
        if has_exceptions {
            // Align to 4-byte boundary
            let rem = bytes_written.checked_rem(4).unwrap_or(0);
            let padding = 4u64.wrapping_sub(rem).checked_rem(4).unwrap_or(0);
            if padding > 0 {
                writer.write_all(&vec![0u8; padding as usize])?;
                bytes_written = bytes_written
                    .checked_add(padding)
                    .ok_or_else(|| malformed_error!("method body byte count overflow"))?;
            }

            // Use the shared exception handler encoding
            let exception_bytes =
                encode_exception_handlers(&self.exception_handlers, self.exception_format)?;
            writer.write_all(&exception_bytes)?;
            bytes_written = bytes_written
                .checked_add(exception_bytes.len() as u64)
                .ok_or_else(|| malformed_error!("method body byte count overflow"))?;
        }

        Ok(bytes_written)
    }
}

#[cfg(test)]
mod tests {
    use proptest::{prop_assert, prop_assert_eq, test_runner::TestCaseError};

    use super::*;
    use crate::{
        metadata::method::ExceptionHandlerFlags,
        testkit::{arb, arb::check},
    };

    #[test]
    fn tiny() {
        /*
        WindowsBase.dll

        HeaderRVA:          0xF7358
        HeaderOffset:       0xF7358
        MaxStack:           8
        LocalVarSigToken:   0
        Locals:             0
        ExceptionHandlers:  0
        Instructions:       4
        CodeSize:           17
        Size:               18
        Flags:
            - InitLocals
        */

        let data = include_bytes!("../../../tests/samples/WB_METHOD_TINY_0600032D.bin");

        let method_header = MethodBody::from(data).unwrap();

        assert!(!method_header.is_fat);
        assert!(!method_header.is_exception_data);
        assert!(!method_header.is_init_local);
        assert_eq!(method_header.max_stack, 8);
        assert_eq!(method_header.size_code, 18);
        assert_eq!(method_header.size_header, 1);
        assert_eq!(method_header.size(), 19);
        assert_eq!(method_header.local_var_sig_token, 0);
    }

    #[test]
    fn fat() {
        /*
        WindowsBase.dll

        HeaderRVA:          0xF77D8
        HeaderOffset:       0xF77D8
        MaxStack:           5
        LocalVarSigToken:   0x11000059
        Locals:             4
        ExceptionHandlers:  0
        Instructions:       79
        CodeSize:           0x9B
        Flags:
            - InitLocals
        */

        let data = include_bytes!("../../../tests/samples/WB_METHOD_FAT_0600033E.bin");

        let method_header = MethodBody::from(data).unwrap();

        assert!(method_header.is_fat);
        assert!(!method_header.is_exception_data);
        assert!(method_header.is_init_local);
        assert_eq!(method_header.max_stack, 5);
        assert_eq!(method_header.size_code, 0x9B);
        assert_eq!(method_header.size_header, 12);
        assert_eq!(method_header.size(), 167);
        assert_eq!(method_header.local_var_sig_token, 0x11000059);
    }

    #[test]
    fn fat_exceptions_1() {
        /*
        WindowsBase.dll

        HeaderRVA:          0xF7898
        HeaderOffset:       0xF7898
        MaxStack:           1
        LocalVarSigToken:   0x11000003
        Locals:             1
        ExceptionHandlers:  1
        Instructions:       15
        CodeSize:           0x1C
        Flags:
            - InitLocals
        */

        let data = include_bytes!("../../../tests/samples/WB_METHOD_FAT_EXCEPTION_06000341.bin");

        let method_header = MethodBody::from(data).unwrap();

        assert!(method_header.is_fat);
        assert!(method_header.is_exception_data);
        assert!(method_header.is_init_local);
        assert_eq!(method_header.max_stack, 1);
        assert_eq!(method_header.size_code, 30);
        assert_eq!(method_header.size_header, 12);
        assert_eq!(method_header.size(), 60); // 44 (aligned base) + 16 (small exception section)
        assert_eq!(method_header.local_var_sig_token, 0x11000003);
        assert_eq!(method_header.exception_handlers.len(), 1);
        assert!(method_header.exception_handlers[0]
            .flags
            .contains(ExceptionHandlerFlags::EXCEPTION));
        assert_eq!(method_header.exception_handlers[0].try_offset, 0);
        assert_eq!(method_header.exception_handlers[0].try_length, 0xF);
        assert_eq!(method_header.exception_handlers[0].handler_offset, 0xF);
        assert_eq!(method_header.exception_handlers[0].handler_length, 0xD);
        assert_eq!(method_header.exception_handlers[0].filter_offset, 0x100003F);
    }

    #[test]
    fn fat_exceptions_tiny_section_2() {
        /*
        WindowsBase.dll

        HeaderRVA:          0xECC4C
        HeaderOffset:       0xECC4C
        MaxStack:           3
        LocalVarSigToken:   0x1100001A
        Locals:             2
        ExceptionHandlers:  1
        Instructions:       18
        CodeSize:           0x2D
        Flags:
            - InitLocals
        */

        let data = include_bytes!(
            "../../../tests/samples/WB_METHOD_FAT_EXCEPTION_N1_2LOCALS_060001AA.bin"
        );

        let method_header = MethodBody::from(data).unwrap();

        assert!(method_header.is_fat);
        assert!(method_header.is_exception_data);
        assert!(method_header.is_init_local);
        assert_eq!(method_header.max_stack, 3);
        assert_eq!(method_header.size_code, 0x2E);
        assert_eq!(method_header.size_header, 12);
        assert_eq!(method_header.size(), 76); // 60 (aligned base) + 16 (small exception section)
        assert_eq!(method_header.local_var_sig_token, 0x1100001A);
        assert_eq!(method_header.exception_handlers.len(), 1);
        assert!(method_header.exception_handlers[0]
            .flags
            .contains(ExceptionHandlerFlags::FINALLY));
        assert_eq!(method_header.exception_handlers[0].try_offset, 0x8);
        assert_eq!(method_header.exception_handlers[0].try_length, 0x1B);
        assert_eq!(method_header.exception_handlers[0].handler_offset, 0x23);
        assert_eq!(method_header.exception_handlers[0].handler_length, 0xA);
        assert_eq!(method_header.exception_handlers[0].filter_offset, 0);
    }

    #[test]
    fn fat_exceptions_fat_section_3() {
        /*
        WindowsBase.dll

        HeaderRVA:          0xF9839
        HeaderOffset:       0xF9839
        MaxStack:           5
        LocalVarSigToken:   0x11000070
        Locals:             10
        ExceptionHandlers:  2
        Instructions:       156
        CodeSize:           0x19F
        Flags:
            - InitLocals
        */

        let data = include_bytes!("../../../tests/samples/WB_METHOD_FAT_EXCEPTION_N2_06000421.bin");

        let method_header = MethodBody::from(data).unwrap();

        assert!(method_header.is_fat);
        assert!(method_header.is_exception_data);
        assert!(method_header.is_init_local);
        assert_eq!(method_header.max_stack, 5);
        assert_eq!(method_header.size_code, 0x19F);
        assert_eq!(method_header.size_header, 12);
        assert_eq!(method_header.size(), 480); // 428 (aligned base) + 52 (fat exception section with 2 handlers)
        assert_eq!(method_header.local_var_sig_token, 0x11000070);
        assert_eq!(method_header.exception_handlers.len(), 2);
        assert!(method_header.exception_handlers[0]
            .flags
            .contains(ExceptionHandlerFlags::FINALLY));
        assert_eq!(method_header.exception_handlers[0].try_offset, 0x145);
        assert_eq!(method_header.exception_handlers[0].try_length, 0x28);
        assert_eq!(method_header.exception_handlers[0].handler_offset, 0x16D);
        assert_eq!(method_header.exception_handlers[0].handler_length, 0xE);
        assert_eq!(method_header.exception_handlers[0].filter_offset, 0);
        assert!(method_header.exception_handlers[1]
            .flags
            .contains(ExceptionHandlerFlags::FINALLY));
        assert_eq!(method_header.exception_handlers[1].try_offset, 0x9);
        assert_eq!(method_header.exception_handlers[1].try_length, 0x18A);
        assert_eq!(method_header.exception_handlers[1].handler_offset, 0x193);
        assert_eq!(method_header.exception_handlers[1].handler_length, 0xA);
        assert_eq!(method_header.exception_handlers[1].filter_offset, 0);
    }

    #[test]
    fn fat_exception_section_write_roundtrips() {
        // Regression for GH #218: the fat exception-section header must be exactly
        // 4 bytes (Kind + 3-byte DataSize), not 6. A 6-byte header shifted DataSize
        // by two bytes, so re-parsing a written-back method read a bogus handler
        // count (e.g. 0x1C0000/24 = 76458) and Mono/IKVM crashed resolving a garbage
        // catch-type token. This method requires the fat section (try_length > 0xFF).
        let data = include_bytes!("../../../tests/samples/WB_METHOD_FAT_EXCEPTION_N2_06000421.bin");
        let original = MethodBody::from(data).unwrap();
        assert_eq!(original.exception_handlers.len(), 2);

        // Extract the IL and re-serialize via the writer path.
        let il = &data[original.size_header..original.size_header + original.size_code];
        let mut written = Vec::new();
        original.write_to(&mut written, il).unwrap();

        // The written bytes must parse back to the exact same handlers.
        let reparsed = MethodBody::from(&written).unwrap();
        assert!(reparsed.is_fat);
        assert!(reparsed.is_exception_data);
        assert_eq!(reparsed.size_code, original.size_code);
        assert_eq!(reparsed.local_var_sig_token, original.local_var_sig_token);
        assert_eq!(
            reparsed.exception_handlers.len(),
            original.exception_handlers.len(),
            "handler count must survive a write/parse round-trip"
        );
        for (a, b) in original
            .exception_handlers
            .iter()
            .zip(reparsed.exception_handlers.iter())
        {
            assert_eq!(a.flags.bits(), b.flags.bits());
            assert_eq!(a.try_offset, b.try_offset);
            assert_eq!(a.try_length, b.try_length);
            assert_eq!(a.handler_offset, b.handler_offset);
            assert_eq!(a.handler_length, b.handler_length);
            assert_eq!(a.filter_offset, b.filter_offset);
        }
    }

    #[test]
    fn fat_exceptions_multiple() {
        /*
        WindowsBase.dll

        HeaderRVA:          0x114140
        HeaderOffset:       0x114140
        MaxStack:           3
        LocalVarSigToken:   0x1100007C
        Locals:             2
        ExceptionHandlers:  2
        Instructions:       32
        CodeSize:           0x51
        Flags:
            - InitLocals
        */

        let data = include_bytes!("../../../tests/samples/WB_METHOD_FAT_EXCEPTION_N2_06000D54.bin");

        let method_header = MethodBody::from(data).unwrap();

        assert!(method_header.is_fat);
        assert!(method_header.is_exception_data);
        assert!(method_header.is_init_local);
        assert_eq!(method_header.max_stack, 3);
        assert_eq!(method_header.size_code, 81);
        assert_eq!(method_header.size_header, 12);
        assert_eq!(method_header.size(), 124); // 96 (aligned base) + 28 (small exception section with 2 handlers)
        assert_eq!(method_header.local_var_sig_token, 0x1100007C);

        assert_eq!(method_header.exception_handlers.len(), 2);
        assert!(method_header.exception_handlers[0]
            .flags
            .contains(ExceptionHandlerFlags::FINALLY));
        assert_eq!(method_header.exception_handlers[0].try_offset, 17);
        assert_eq!(method_header.exception_handlers[0].try_length, 48);
        assert_eq!(method_header.exception_handlers[0].handler_offset, 65);
        assert_eq!(method_header.exception_handlers[0].handler_length, 10);
        assert_eq!(method_header.exception_handlers[0].filter_offset, 0);

        assert!(method_header.exception_handlers[1]
            .flags
            .contains(ExceptionHandlerFlags::EXCEPTION));
        assert_eq!(method_header.exception_handlers[1].try_offset, 0);
        assert_eq!(method_header.exception_handlers[1].try_length, 77);
        assert_eq!(method_header.exception_handlers[1].handler_offset, 77);
        assert_eq!(method_header.exception_handlers[1].handler_length, 3);
        assert_eq!(method_header.exception_handlers[1].filter_offset, 0x100001D);
    }

    /// Helper: builds a fat method body with the given small-format EH clauses.
    /// Each clause is (flags_u16, try_offset_u16, try_length_u8, handler_offset_u16, handler_length_u8, filter_offset_u32).
    fn build_fat_body_with_small_eh(
        code_size: u32,
        clauses: &[(u16, u16, u8, u16, u8, u32)],
    ) -> Vec<u8> {
        let il_code = vec![0x00u8; code_size as usize];

        // Fat header: FAT_FORMAT | MORE_SECTS | INIT_LOCALS, size=3 dwords
        let flags: u16 = 0x3003 | 0x0008 | 0x0010;
        let max_stack: u16 = 8;
        let local_var_sig: u32 = 0;

        let mut data = Vec::new();
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(&max_stack.to_le_bytes());
        data.extend_from_slice(&code_size.to_le_bytes());
        data.extend_from_slice(&local_var_sig.to_le_bytes());
        data.extend_from_slice(&il_code);

        // Align to 4 bytes
        let unaligned = 12 + code_size as usize;
        let aligned = (unaligned + 3) & !3;
        data.extend(std::iter::repeat_n(0x00, aligned - unaligned));

        // Small exception section header
        let section_size = (4 + clauses.len() * 12) as u8;
        data.push(0x01); // section flags: EHTABLE
        data.push(section_size);
        data.push(0x00); // padding
        data.push(0x00); // padding

        for &(flags, try_off, try_len, handler_off, handler_len, filter) in clauses {
            data.extend_from_slice(&flags.to_le_bytes());
            data.extend_from_slice(&try_off.to_le_bytes());
            data.push(try_len);
            data.extend_from_slice(&handler_off.to_le_bytes());
            data.push(handler_len);
            data.extend_from_slice(&filter.to_le_bytes());
        }

        data
    }

    #[test]
    fn from_lenient_filters_invalid_handlers() {
        // Build a fat method with 3 EH entries: 1 valid, 2 with out-of-bounds offsets.
        // Code size = 100 bytes
        let clauses = [
            // Valid handler: try=[0..10), handler=[10..20)
            (0x0000u16, 0u16, 10u8, 10u16, 10u8, 0x01000001u32),
            // Invalid: try_offset way beyond code
            (0x0000, 0xFFFF, 0xFF, 0xFFFF, 0xFF, 0x01000001),
            // Invalid: handler_offset beyond code
            (0x0000, 0, 5, 0xAAAA, 0xBB, 0x01000001),
        ];
        let data = build_fat_body_with_small_eh(100, &clauses);

        // Strict from() should fail
        assert!(MethodBody::from(&data).is_err());

        // Lenient should keep only the valid handler and report 2 filtered
        let (body, filtered) = MethodBody::from_lenient(&data).unwrap();
        assert!(body.is_fat);
        assert_eq!(body.size_code, 100);
        assert_eq!(body.exception_handlers.len(), 1);
        assert_eq!(filtered, 2);
        // The valid handler should be the one kept
        assert_eq!(body.exception_handlers[0].try_offset, 0);
        assert_eq!(body.exception_handlers[0].try_length, 10);
        assert_eq!(body.exception_handlers[0].handler_offset, 10);
        assert_eq!(body.exception_handlers[0].handler_length, 10);
    }

    #[test]
    fn from_raw_keeps_all_handlers() {
        // Same test data as above: 1 valid + 2 invalid handlers
        let clauses = [
            (0x0000u16, 0u16, 10u8, 10u16, 10u8, 0x01000001u32),
            (0x0000, 0xFFFF, 0xFF, 0xFFFF, 0xFF, 0x01000001),
            (0x0000, 0, 5, 0xAAAA, 0xBB, 0x01000001),
        ];
        let data = build_fat_body_with_small_eh(100, &clauses);

        // Raw should keep all 3 handlers
        let body = MethodBody::from_raw(&data).unwrap();
        assert_eq!(body.exception_handlers.len(), 3);
        // Verify the garbage handler is preserved
        assert_eq!(body.exception_handlers[1].try_offset, 0xFFFF);
    }

    #[test]
    fn from_lenient_accepts_malformed_eh() {
        // Construct a fat method with a single exception handler whose
        // try region extends far beyond the code size (malformed).
        let clauses = [
            // Invalid: try_offset way beyond code
            (
                0x0000u16,
                0xFFFFu16,
                0xFFu8,
                0xFFFFu16,
                0xFFu8,
                0x01000001u32,
            ),
        ];
        let data = build_fat_body_with_small_eh(10, &clauses);

        // Strict from() should fail due to bad EH bounds
        assert!(MethodBody::from(&data).is_err());

        // Lenient from_lenient() should succeed, filtering out the invalid handler
        let (body, filtered) = MethodBody::from_lenient(&data).unwrap();
        assert!(body.is_fat);
        assert_eq!(body.size_code, 10);
        assert_eq!(filtered, 1);
        assert_eq!(body.exception_handlers.len(), 0);

        // Raw from_raw() should keep the handler
        let raw_body = MethodBody::from_raw(&data).unwrap();
        assert_eq!(raw_body.exception_handlers.len(), 1);
        assert_eq!(raw_body.exception_handlers[0].try_offset, 0xFFFF);
    }

    /// Builds a fat method body whose header-size nibble is `header_dwords`.
    ///
    /// `size_code` bytes of IL follow the header. The IL is a run of `nop` so a mis-located
    /// start is visible as a wrong `size_code`/`size_header` rather than as a decode error.
    fn build_fat_body_with_header_dwords(header_dwords: u16, size_code: u32) -> Vec<u8> {
        let mut data = Vec::new();
        // flags (fat, init-locals) in the low 12 bits, header size in the top nibble
        let first_duo = (header_dwords << 12) | 0x0013;
        data.extend_from_slice(&first_duo.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes()); // max_stack
        data.extend_from_slice(&size_code.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes()); // local_var_sig_token

        // Pad out to the declared header length, then the IL.
        let header_len = (header_dwords as usize).saturating_mul(4);
        data.resize(header_len, 0);
        data.resize(header_len + size_code as usize, 0x00);
        data
    }

    /// A header shorter than 3 dwords would overlap the code it precedes, so it is refused.
    ///
    /// `size_code` is read from offset 4 and `localVarSigTok` from offset 8; with a header
    /// under 12 bytes the body starts inside its own header and every downstream offset is
    /// wrong. This is the hazard the nibble check exists for.
    #[test]
    fn fat_header_below_three_dwords_is_refused() {
        for dwords in 0..3u16 {
            let data = build_fat_body_with_header_dwords(dwords, 4);
            assert!(
                MethodBody::from(&data).is_err(),
                "a {dwords}-dword fat header must be refused"
            );
        }
    }

    /// A header larger than the mandated 3 dwords is honoured, not rejected and not normalised.
    ///
    /// ECMA-335 II.25.4.3 fixes the value at 3, but CoreCLR and dnlib both locate the IL at
    /// `4 * (flags >> 12)`, so such a body is loadable in practice and a malware-analysis tool
    /// has to read it the same way. Rejecting it refused files the CLR runs; normalising to 12
    /// shifted the IL start, the `size_code` bounds check and the EH cursor by `4 * (n - 3)`
    /// and decoded garbage.
    #[test]
    fn fat_header_above_three_dwords_is_honoured() {
        let data = build_fat_body_with_header_dwords(4, 8);

        let body = MethodBody::from(&data).expect("a 4-dword fat header must load");

        assert!(body.is_fat);
        assert_eq!(body.size_header, 16, "the declared header size is honoured");
        assert_eq!(body.size_code, 8);
        assert_eq!(body.max_stack, 1);
    }

    /// The mandated 3-dword header is unaffected by the above.
    #[test]
    fn fat_header_of_three_dwords_is_unchanged() {
        let data = build_fat_body_with_header_dwords(3, 8);

        let body = MethodBody::from(&data).expect("a conformant fat header must load");

        assert_eq!(body.size_header, 12);
        assert_eq!(body.size_code, 8);
    }

    /// A fat body writes back fat, though the tiny format would hold its code: its maximum
    /// stack and `InitLocals` are part of what it says.
    #[test]
    fn a_fat_body_writes_back_fat() {
        // Fat header: InitLocals, max stack 3, 2 bytes of code, no locals
        let mut data = vec![
            0x13, 0x30, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        data.extend_from_slice(&[0x17, 0x2A]);
        let body = MethodBody::from(&data).unwrap();
        assert!(body.is_fat);

        let mut written = Vec::new();
        body.write_to(&mut written, &data[12..]).unwrap();
        assert_eq!(written, data);
    }

    /// A fat body of 8 bytes of code whose header says sections follow, then `sections`.
    fn with_sections(sections: &[&[u8]]) -> Vec<u8> {
        let mut body = vec![0x0B, 0x30, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0, 0, 0, 0];
        body.extend_from_slice(&[0x00; 7]);
        body.push(0x2A);
        for section in sections {
            body.extend_from_slice(section);
        }
        body
    }

    /// A small section header and its clauses.
    fn small_section(kind: u8, data_size: u8, clauses: &[[u8; 12]]) -> Vec<u8> {
        let mut section = vec![kind, data_size, 0x00, 0x00];
        for clause in clauses {
            section.extend_from_slice(clause);
        }
        section
    }

    /// A small finally clause protecting [0, 2) with a handler at [2, 4), and `token` in its
    /// class token field.
    fn finally_clause(token: u32) -> [u8; 12] {
        let mut clause = [0x02, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x02, 0, 0, 0, 0];
        clause[8..].copy_from_slice(&token.to_le_bytes());
        clause
    }

    fn rewritten(data: &[u8]) -> Vec<u8> {
        let body = MethodBody::from(data).unwrap();
        let mut written = Vec::new();
        body.write_to(&mut written, &data[12..20]).unwrap();
        written
    }

    #[test]
    fn an_exception_section_is_written_back_in_the_format_it_was_read() {
        // A fat section for a clause the small format holds (CoreLib's compilers write them)
        let mut fat = vec![0x41, 0x1C, 0x00, 0x00];
        fat.extend_from_slice(&[0x02, 0, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0]);
        fat.extend_from_slice(&[0x02, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, 0]);
        let data = with_sections(&[&fat]);
        let body = MethodBody::from(&data).unwrap();
        assert_eq!(
            body.exception_format,
            Some(ExceptionSectionFormat {
                fat: true,
                data_size: 0x1C
            })
        );
        assert_eq!(rewritten(&data), data);

        // A small section whose DataSize leaves out its header, as AsmResolver writes it
        let clauses = [finally_clause(0), finally_clause(0)];
        let data = with_sections(&[&small_section(0x01, 24, &clauses)]);
        assert_eq!(MethodBody::from(&data).unwrap().exception_handlers.len(), 2);
        assert_eq!(rewritten(&data), data);

        // A finally clause's class token field is written back as it was
        let data = with_sections(&[&small_section(0x01, 16, &[finally_clause(0x0100_0001)])]);
        assert_eq!(rewritten(&data), data);
    }

    #[test]
    fn a_new_clause_count_gets_the_ecma_data_size() {
        let data = with_sections(&[&small_section(0x01, 12, &[finally_clause(0)])]);
        let mut body = MethodBody::from(&data).unwrap();
        body.exception_handlers
            .push(body.exception_handlers[0].clone());
        let mut written = Vec::new();
        body.write_to(&mut written, &data[12..20]).unwrap();
        assert_eq!(&written[20..24], &[0x01, 28, 0x00, 0x00]);
        assert_eq!(
            MethodBody::from(&written).unwrap().exception_handlers.len(),
            2
        );
    }

    #[test]
    fn data_sections_are_walked_as_the_runtime_walks_them() {
        // A section of another kind before the EH table is skipped, not the end
        let other = [0x82, 0x08, 0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD];
        let eh = small_section(0x01, 16, &[finally_clause(0)]);
        let body = MethodBody::from(&with_sections(&[&other, &eh])).unwrap();
        assert_eq!(body.exception_handlers.len(), 1);

        // Only the first EH table holds the method's handlers: a later one is ignored
        let first = small_section(0x81, 16, &[finally_clause(0)]);
        let decoy = small_section(0x01, 28, &[finally_clause(0), finally_clause(0)]);
        let body = MethodBody::from(&with_sections(&[&first, &decoy])).unwrap();
        assert_eq!(body.exception_handlers.len(), 1);

        // A kind with more than the EH table bit set is not an EH table
        let both = small_section(0x03, 16, &[finally_clause(0)]);
        let body = MethodBody::from(&with_sections(&[&both])).unwrap();
        assert!(body.exception_handlers.is_empty());
    }

    #[test]
    fn a_method_may_have_any_number_of_handlers() {
        let mut fat = Vec::new();
        let count: u32 = 1500;
        fat.push(0x41);
        fat.extend_from_slice(&(4 + count * 24).to_le_bytes()[..3]);
        for _ in 0..count {
            for field in [0x02u32, 0, 2, 2, 2, 0] {
                fat.extend_from_slice(&field.to_le_bytes());
            }
        }
        let data = with_sections(&[&fat]);
        assert_eq!(
            MethodBody::from(&data).unwrap().exception_handlers.len(),
            1500
        );
        assert_eq!(rewritten(&data), data);
    }

    #[test]
    fn a_truncated_exception_section_is_an_error_unless_lenient() {
        let mut eh = small_section(0x01, 28, &[finally_clause(0)]);
        eh.truncate(10);
        let data = with_sections(&[&eh]);
        assert!(MethodBody::from(&data).is_err());
        let (body, _) = MethodBody::from_lenient(&data).unwrap();
        assert!(body.exception_handlers.is_empty());

        // MoreSects with no section after the code
        let data = with_sections(&[]);
        assert!(MethodBody::from(&data).is_err());
    }

    /// Every body decodes to what was written: its header, code, clauses and exception section
    /// format, and writing what was decoded gives the same bytes.
    #[test]
    fn every_body_decodes_to_what_was_written() {
        check(arb::method_body(), |(body, code)| {
            let mut bytes = Vec::new();
            body.write_to(&mut bytes, &code)
                .map_err(|error| TestCaseError::fail(format!("does not encode: {error}")))?;
            let decoded = MethodBody::from(&bytes).map_err(|error| {
                TestCaseError::fail(format!("{bytes:02x?} does not decode: {error}"))
            })?;
            prop_assert_eq!(decoded.is_fat, body.is_fat);
            prop_assert_eq!(decoded.size_header, body.size_header);
            prop_assert_eq!(decoded.size_code, body.size_code);
            prop_assert_eq!(decoded.max_stack, body.max_stack);
            prop_assert_eq!(decoded.local_var_sig_token, body.local_var_sig_token);
            prop_assert_eq!(decoded.is_init_local, body.is_init_local);
            prop_assert_eq!(
                &bytes[decoded.size_header..decoded.size_header + decoded.size_code],
                &code[..]
            );
            let clause = |eh: &ExceptionHandler| {
                (
                    eh.flags,
                    eh.try_offset,
                    eh.try_length,
                    eh.handler_offset,
                    eh.handler_length,
                    eh.filter_offset,
                )
            };
            let read: Vec<_> = decoded.exception_handlers.iter().map(clause).collect();
            let written: Vec<_> = body.exception_handlers.iter().map(clause).collect();
            prop_assert_eq!(read, written);
            if body.exception_format.is_some() {
                prop_assert_eq!(decoded.exception_format, body.exception_format);
            }
            prop_assert!(decoded.is_exception_data == !body.exception_handlers.is_empty());

            let mut again = Vec::new();
            decoded
                .write_to(&mut again, &code)
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            prop_assert_eq!(again, bytes);
            Ok(())
        });
    }
}

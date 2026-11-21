//! `ImplMap` table implementation for Platform Invoke (P/Invoke) mappings.
//!
//! This module provides complete support for the `ImplMap` metadata table, which defines
//! Platform Invoke mappings that enable managed code to call unmanaged functions in
//! native libraries. The `ImplMap` table is essential for native interoperability scenarios.
//!
//! # Module Components
//! - [`ImplMapRaw`] - Raw table structure with unresolved coded indexes
//! - [`ImplMap`] - Owned variant with resolved references and owned data
//! - [`ImplMapLoader`](crate::metadata::loader::tables::ImplMapLoader) - Internal loader for processing table entries (crate-private)
//! - [`crate::metadata::tables::PInvokeAttributes`] - Strongly-typed P/Invoke attribute flags
//! - Type aliases for collections: [`ImplMapMap`], [`ImplMapList`], [`ImplMapRc`]
//!
//! # Table Structure (ECMA-335 §22.22)
//! | Column | Type | Description |
//! |--------|------|-------------|
//! | `MappingFlags` | 2-byte flags | P/Invoke attributes (calling convention, charset, etc.) |
//! | `MemberForwarded` | 2-byte coded index | Member being forwarded to native function |
//! | `ImportName` | String heap index | Name of the target function in the native library |
//! | `ImportScope` | `ModuleRef` index | Target module (native library) containing the function |
//!
//! # P/Invoke Functionality
//! The `ImplMap` table enables native interoperability through:
//! - **Method mapping**: Associates managed methods with native functions
//! - **Library specification**: Identifies target native libraries via `ModuleRef`
//! - **Calling conventions**: Specifies how parameters are passed and cleaned up
//! - **Character encoding**: Controls string marshalling (ANSI, Unicode, Auto)
//! - **Error handling**: Manages `GetLastError()` propagation and exception mapping
//!
//! # Mapping Flags
//! The [`crate::metadata::tables::PInvokeAttributes`] type defines flags controlling P/Invoke behavior:
//! - **Name mangling**: [`NO_MANGLE`] preserves exact function names
//! - **Character sets**: [`CHAR_SET_ANSI`], [`CHAR_SET_UNICODE`], [`CHAR_SET_AUTO`]
//! - **Calling conventions**: [`CALL_CONV_CDECL`], [`CALL_CONV_STDCALL`], etc.
//! - **Error handling**: [`SUPPORTS_LAST_ERROR`] for `GetLastError()` support
//! - **String mapping**: [`BEST_FIT_ENABLED`], [`THROW_ON_UNMAPPABLE_ENABLED`]
//!
//! # ECMA-335 References
//! - ECMA-335, Partition II, §22.22: `ImplMap` table specification
//! - ECMA-335, Partition II, §23.1.8: `MemberForwarded` coded index encoding
//! - ECMA-335, Partition II, §15.5: Platform invoke attributes and marshalling
//!
//! [`NO_MANGLE`]: PInvokeAttributes::NO_MANGLE
//! [`CHAR_SET_ANSI`]: PInvokeAttributes::CHAR_SET_ANSI
//! [`CHAR_SET_UNICODE`]: PInvokeAttributes::CHAR_SET_UNICODE
//! [`CHAR_SET_AUTO`]: PInvokeAttributes::CHAR_SET_AUTO
//! [`CALL_CONV_CDECL`]: PInvokeAttributes::CALL_CONV_CDECL
//! [`CALL_CONV_STDCALL`]: PInvokeAttributes::CALL_CONV_STDCALL
//! [`SUPPORTS_LAST_ERROR`]: PInvokeAttributes::SUPPORTS_LAST_ERROR
//! [`BEST_FIT_ENABLED`]: PInvokeAttributes::BEST_FIT_ENABLED
//! [`THROW_ON_UNMAPPABLE_ENABLED`]: PInvokeAttributes::THROW_ON_UNMAPPABLE_ENABLED
use std::sync::Arc;

use crossbeam_skiplist::SkipMap;

use crate::metadata::token::Token;

mod builder;
mod owned;
mod raw;
mod reader;
mod writer;

pub use builder::*;
pub use owned::*;
pub use raw::*;

/// Concurrent map for storing `ImplMap` entries indexed by [`crate::metadata::token::Token`].
///
/// This thread-safe map enables efficient lookup of P/Invoke mappings by their
/// associated member tokens during metadata processing and runtime method resolution.
pub type ImplMapMap = SkipMap<Token, ImplMapRc>;

/// Thread-safe list for storing collections of `ImplMap` entries.
///
/// Used for maintaining ordered sequences of P/Invoke mappings during metadata
/// loading and for iteration over all native interop declarations in a module.
pub type ImplMapList = Arc<boxcar::Vec<ImplMapRc>>;

/// Reference-counted pointer to an [`ImplMap`] instance.
///
/// Enables efficient sharing of P/Invoke mapping data across multiple contexts
/// without duplication, supporting concurrent access patterns in metadata processing.
pub type ImplMapRc = Arc<ImplMap>;

metadata_flags! {
    /// Platform Invoke (P/Invoke) attribute flags (ECMA-335 §II.23.1.8).
    ///
    /// Strongly-typed wrapper around the 2-byte `ImplMap.MappingFlags` bitmask controlling
    /// Platform Invoke behavior when calling native functions from managed code. These flags
    /// control calling conventions, character set marshalling, error handling, and name mangling.
    ///
    /// # Flag Categories
    /// - **Name mangling**: Controls whether function names are modified during lookup
    /// - **Character sets**: Specifies string encoding for parameter marshalling
    /// - **Calling conventions**: Defines parameter passing and stack cleanup behavior
    /// - **Error handling**: Controls `GetLastError()` propagation and exception mapping
    /// - **String mapping**: Configures character conversion and unmappable character handling
    ///
    /// # Usage in P/Invoke Declarations
    /// These flags are typically combined using bitwise OR operations to specify
    /// the complete marshalling behavior for a native function call.
    pub struct PInvokeAttributes(u32);
}

impl PInvokeAttributes {
    /// Use the member name exactly as specified without name mangling.
    ///
    /// When set, prevents the runtime from applying platform-specific name
    /// decoration (such as prefixing underscores or appending calling convention suffixes).
    pub const NO_MANGLE: Self = Self(0x0001);

    /// Character set not specified - use platform default.
    ///
    /// Default character encoding behavior, typically ANSI on Windows.
    pub const CHAR_SET_NOT_SPEC: Self = Self(0x0000);

    /// Use ANSI character encoding for string parameters.
    ///
    /// String parameters are marshalled as narrow (single-byte) characters
    /// using the system's default ANSI code page.
    pub const CHAR_SET_ANSI: Self = Self(0x0002);

    /// Use Unicode (UTF-16) character encoding for string parameters.
    ///
    /// String parameters are marshalled as wide (two-byte) Unicode characters.
    pub const CHAR_SET_UNICODE: Self = Self(0x0004);

    /// Use automatic character set selection based on platform.
    ///
    /// The runtime chooses between ANSI and Unicode based on the target platform
    /// and function availability (trying Unicode first, falling back to ANSI).
    pub const CHAR_SET_AUTO: Self = Self(0x0006);

    /// Bit mask for extracting character set flags.
    ///
    /// Use this mask to isolate character encoding flags from other attributes.
    pub const CHAR_SET_MASK: Self = Self(0x0006);

    /// Enable `GetLastError()` support for error propagation.
    ///
    /// When set, the runtime preserves the thread's last error value after
    /// the native call, making it available via `Marshal.GetLastWin32Error()`.
    pub const SUPPORTS_LAST_ERROR: Self = Self(0x0040);

    /// Bit mask for extracting calling convention flags.
    ///
    /// Use this mask to isolate calling convention flags from other attributes.
    pub const CALL_CONV_MASK: Self = Self(0x0700);

    /// Use platform default calling convention (`WinAPI`).
    ///
    /// On Windows, this typically resolves to `StdCall` on x86 and the standard
    /// calling convention on x64. Equivalent to `CALL_CONV_STDCALL` on most platforms.
    pub const CALL_CONV_WINAPI: Self = Self(0x0100);

    /// Use C calling convention (caller cleans stack).
    ///
    /// Parameters pushed right-to-left, caller responsible for stack cleanup.
    /// Variable argument functions typically use this convention.
    pub const CALL_CONV_CDECL: Self = Self(0x0200);

    /// Use standard calling convention (callee cleans stack).
    ///
    /// Parameters pushed right-to-left, callee responsible for stack cleanup.
    /// Most Windows API functions use this convention.
    pub const CALL_CONV_STDCALL: Self = Self(0x0300);

    /// Use this-call calling convention (implicit this parameter).
    ///
    /// First parameter (this pointer) passed in register, remaining parameters
    /// pushed right-to-left. Used for C++ member functions.
    pub const CALL_CONV_THISCALL: Self = Self(0x0400);

    /// Use fast calling convention (register-based parameter passing).
    ///
    /// First few parameters passed in registers for performance, remaining
    /// parameters pushed right-to-left on stack.
    pub const CALL_CONV_FASTCALL: Self = Self(0x0500);

    /// Bit mask for extracting best-fit mapping flags.
    ///
    /// Use this mask to isolate best-fit character mapping flags from other attributes.
    pub const BEST_FIT_MASK: Self = Self(0x0030);

    /// Enable best-fit character mapping for unmappable characters.
    ///
    /// When converting between character encodings, allows substitution of
    /// similar characters when exact matches are not available.
    pub const BEST_FIT_ENABLED: Self = Self(0x0010);

    /// Disable best-fit character mapping.
    ///
    /// Prevents character substitution during encoding conversion, potentially
    /// causing exceptions for unmappable characters.
    pub const BEST_FIT_DISABLED: Self = Self(0x0020);

    /// Bit mask for extracting unmappable character handling flags.
    ///
    /// Use this mask to isolate exception throwing behavior for unmappable characters.
    pub const THROW_ON_UNMAPPABLE_MASK: Self = Self(0x3000);

    /// Throw exceptions when encountering unmappable characters.
    ///
    /// Forces the marshaller to throw an exception when characters cannot be
    /// converted between encodings, ensuring data integrity.
    pub const THROW_ON_UNMAPPABLE_ENABLED: Self = Self(0x1000);

    /// Do not throw exceptions for unmappable characters.
    ///
    /// Allows marshalling to continue with character substitution or omission
    /// when encountering unmappable characters.
    pub const THROW_ON_UNMAPPABLE_DISABLED: Self = Self(0x2000);

    /// Extracts the character set portion of the flags.
    #[inline]
    #[must_use]
    pub const fn char_set(self) -> Self {
        Self(self.0 & Self::CHAR_SET_MASK.0)
    }

    /// Extracts the calling convention portion of the flags.
    #[inline]
    #[must_use]
    pub const fn call_conv(self) -> Self {
        Self(self.0 & Self::CALL_CONV_MASK.0)
    }

    /// Extracts the best-fit mapping portion of the flags.
    #[inline]
    #[must_use]
    pub const fn best_fit(self) -> Self {
        Self(self.0 & Self::BEST_FIT_MASK.0)
    }

    /// Extracts the unmappable character handling portion of the flags.
    #[inline]
    #[must_use]
    pub const fn throw_on_unmappable(self) -> Self {
        Self(self.0 & Self::THROW_ON_UNMAPPABLE_MASK.0)
    }

    /// Returns the ILAsm keyword for the character set portion of the flags.
    #[must_use]
    pub fn char_set_keyword(self) -> &'static str {
        match self.char_set() {
            Self::CHAR_SET_ANSI => "ansi",
            Self::CHAR_SET_UNICODE => "unicode",
            Self::CHAR_SET_AUTO => "autochar",
            _ => "",
        }
    }

    /// Returns the ILAsm keyword for the calling convention portion of the flags.
    #[must_use]
    pub fn call_conv_keyword(self) -> &'static str {
        match self.call_conv() {
            Self::CALL_CONV_WINAPI => "winapi",
            Self::CALL_CONV_CDECL => "cdecl",
            Self::CALL_CONV_STDCALL => "stdcall",
            Self::CALL_CONV_THISCALL => "thiscall",
            Self::CALL_CONV_FASTCALL => "fastcall",
            _ => "",
        }
    }
}

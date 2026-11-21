//! Owned `ImplMap` table structure with resolved references.
//!
//! This module provides the [`ImplMap`] struct, which represents Platform Invoke (P/Invoke)
//! mapping entries with all references resolved and data owned. Unlike [`ImplMapRaw`], this
//! structure contains resolved method references, owned strings, and module references.
//!
//! [`ImplMapRaw`]: crate::metadata::tables::ImplMapRaw

use std::sync::atomic::Ordering;

use crate::{
    metadata::{method::MethodRc, streams::SharedStr, tables::ModuleRefRc, token::Token},
    Result,
};

/// Owned `ImplMap` table entry with resolved references and owned data.
///
/// This structure represents a Platform Invoke (P/Invoke) mapping with all coded indexes
/// resolved to their target structures and string data owned. It defines the mapping
/// between a managed method and a native function in an unmanaged library.
///
/// # Platform Invoke Mapping
/// Each `ImplMap` entry establishes a bridge between managed and native code:
/// - **Managed side**: Method definition in the current assembly
/// - **Native side**: Function in an external native library
/// - **Marshalling**: Controlled by mapping flags for calling conventions and data conversion
pub struct ImplMap {
    /// Row identifier within the `ImplMap` table.
    ///
    /// Unique identifier for this P/Invoke mapping entry, used for internal
    /// table management and cross-references.
    pub rid: u32,

    /// Metadata token identifying this `ImplMap` entry.
    ///
    /// The token enables efficient lookup and reference to this P/Invoke mapping
    /// from other metadata structures and runtime systems.
    pub token: Token,

    /// Byte offset of this entry within the raw table data.
    ///
    /// Used for efficient table navigation and binary metadata processing.
    pub offset: usize,

    /// Platform Invoke attribute flags controlling marshalling behavior.
    ///
    /// A 2-byte bitmask specifying calling conventions, character sets, error handling,
    /// and other P/Invoke characteristics. See [`crate::metadata::tables::PInvokeAttributes`] for flag definitions.
    ///
    /// [`crate::metadata::tables::PInvokeAttributes`]: crate::metadata::tables::implmap::PInvokeAttributes
    pub mapping_flags: u32,

    /// Resolved reference to the managed method being forwarded to native code.
    ///
    /// Points to the managed method definition that will invoke the native function.
    /// While the ECMA-335 specification allows both Field and `MethodDef` references,
    /// in practice only `MethodDef` is used since field export is not supported.
    pub member_forwarded: MethodRc,

    /// Name of the target function in the native library.
    ///
    /// Owned string containing the exact function name to be called in the native
    /// library. May be subject to name mangling based on the [`mapping_flags`].
    ///
    /// [`mapping_flags`]: Self::mapping_flags
    pub import_name: SharedStr,

    /// Resolved reference to the module containing the target native function.
    ///
    /// Points to the `ModuleRef` entry that identifies the native library (DLL)
    /// containing the function to be invoked.
    pub import_scope: ModuleRefRc,
}

impl ImplMap {
    /// Applies P/Invoke mapping flags to the target method.
    ///
    /// This method updates the managed method with the P/Invoke attributes defined
    /// in this mapping, enabling the runtime to properly marshal calls to the native
    /// function. The mapping flags are stored atomically in the method's P/Invoke
    /// flags field for thread-safe access.
    ///
    /// # Returns
    /// * `Ok(())` - P/Invoke flags applied successfully
    /// * `Err(_)` - Reserved for future error conditions (currently infallible)
    /// # Errors
    ///
    /// This function never returns an error; it always returns `Ok(())`.
    pub fn apply(&self) -> Result<()> {
        self.member_forwarded
            .flags_pinvoke
            .store(self.mapping_flags, Ordering::Relaxed);

        Ok(())
    }
}

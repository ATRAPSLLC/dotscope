//! Raw `ImplMap` table structure with unresolved coded indexes.
//!
//! This module provides the [`ImplMapRaw`] struct, which represents Platform Invoke (P/Invoke)
//! mapping entries as stored in the metadata stream. The structure contains unresolved
//! coded indexes and string heap references that require processing to become usable.
//!
//! # Purpose
//! [`ImplMapRaw`] serves as the direct representation of `ImplMap` table entries from
//! the binary metadata stream, before reference resolution and string lookup. This
//! raw format is processed during metadata loading to create [`ImplMap`] instances
//! with resolved references and owned data.
//!
//! [`ImplMap`]: crate::metadata::tables::ImplMap

use std::sync::{atomic::Ordering, Arc};

use crate::{
    metadata::{
        imports::Imports,
        method::MethodMap,
        streams::Strings,
        tables::{
            CodedIndex, CodedIndexType, ImplMap, ImplMapRc, ModuleRefMap, TableId, TableInfoRef,
            TableRow,
        },
        token::Token,
        typesystem::CilTypeReference,
    },
    Result,
};

/// Raw `ImplMap` table entry with unresolved coded indexes and heap references.
///
/// This structure represents a Platform Invoke (P/Invoke) mapping entry as stored
/// directly in the metadata stream. All references are unresolved coded indexes
/// or heap offsets that require processing during metadata loading.
///
/// # Table Structure (ECMA-335 §22.22)
/// | Column | Size | Description |
/// |--------|------|-------------|
/// | `MappingFlags` | 2 bytes | P/Invoke attribute flags |
/// | `MemberForwarded` | Coded index | Method or field being forwarded (typically `MethodDef`) |
/// | `ImportName` | String index | Name of target function in native library |
/// | `ImportScope` | `ModuleRef` index | Target module containing the native function |
///
/// # Coded Index Resolution
/// The `member_forwarded` field uses the `MemberForwarded` coded index encoding:
/// - **Tag 0**: Field table (not supported for exports)
/// - **Tag 1**: `MethodDef` table (standard case for P/Invoke)
#[derive(Clone, Debug)]
pub struct ImplMapRaw {
    /// Row identifier within the `ImplMap` table.
    ///
    /// Unique identifier for this P/Invoke mapping entry, used for internal
    /// table management and token generation.
    pub rid: u32,

    /// Metadata token for this `ImplMap` entry (`TableId` 0x1C).
    ///
    /// Computed as `0x1C000000 | rid` to create the full token value
    /// for referencing this P/Invoke mapping from other metadata structures.
    pub token: Token,

    /// Byte offset of this entry within the raw table data.
    ///
    /// Used for efficient table navigation and binary metadata processing.
    pub offset: usize,

    /// Platform Invoke attribute flags as a 2-byte bitmask.
    ///
    /// Defines calling conventions, character sets, error handling, and other
    /// P/Invoke characteristics. See ECMA-335 §23.1.8 and [`crate::metadata::tables::PInvokeAttributes`]
    /// for detailed flag definitions.
    ///
    /// [`crate::metadata::tables::PInvokeAttributes`]: crate::metadata::tables::implmap::PInvokeAttributes
    pub mapping_flags: u32,

    /// `MemberForwarded` coded index to the method or field being mapped.
    ///
    /// Points to either a Field or `MethodDef` table entry (ECMA-335 §24.2.6).
    /// In practice, only `MethodDef` is used since field export is not supported.
    /// Requires resolution during processing to obtain the actual method reference.
    pub member_forwarded: CodedIndex,

    /// String heap index for the target function name.
    ///
    /// References the name of the native function to be called in the target
    /// library. Requires string heap lookup to obtain the actual function name.
    pub import_name: u32,

    /// `ModuleRef` table index for the target native library.
    ///
    /// References the module containing the native function to be invoked.
    /// Requires `ModuleRef` table lookup to obtain the library reference.
    pub import_scope: u32,
}

impl ImplMapRaw {
    /// Applies P/Invoke mapping directly to referenced method and import system.
    ///
    /// This method resolves references and immediately applies the P/Invoke configuration
    /// to the target method and import tracking system. It's an alternative to the
    /// two-step process of conversion to owned structure followed by application.
    ///
    /// # Arguments
    /// * `strings` - String heap for resolving import function names
    /// * `modules` - `ModuleRef` map for resolving target library references
    /// * `methods` - `MethodDef` map for resolving target method references
    /// * `imports` - Import tracking system for registering P/Invoke mappings
    ///
    /// * `Ok(())` - P/Invoke mapping applied successfully
    /// * `Err(_)` - Reference resolution failed or invalid coded index
    ///
    /// # Errors
    /// - Invalid `member_forwarded` token or unsupported table reference
    /// - Method reference cannot be resolved in the `MethodDef` map
    /// - `ModuleRef` reference cannot be resolved
    /// - String heap lookup fails for import name
    pub fn apply(
        &self,
        strings: &Strings,
        modules: &ModuleRefMap,
        methods: &MethodMap,
        imports: &Imports,
    ) -> Result<()> {
        match self.member_forwarded.tag {
            TableId::MethodDef => match methods.get(&self.member_forwarded.token) {
                Some(method) => {
                    method
                        .value()
                        .flags_pinvoke
                        .store(self.mapping_flags, Ordering::Relaxed);

                    match modules.get(&Token::new(self.import_scope | 0x1A00_0000)) {
                        Some(module_ref) => {
                            let import_name = strings.get_shared(self.import_name as usize)?;
                            imports.add_method(
                                import_name,
                                &self.token,
                                method.value().clone(),
                                module_ref.value(),
                            )
                        }
                        None => Err(malformed_error!(
                            "Failed to resolve import_scope token - {}",
                            self.import_scope | 0x1A00_0000
                        )),
                    }
                }
                None => Err(malformed_error!(
                    "Failed to resolve member_forwarded token - {}",
                    self.member_forwarded.token.value()
                )),
            },
            /* According to ECMA-355 TableId::Field is not supported and should not appear */
            _ => Err(malformed_error!(
                "Invalid member_forwarded token - {}",
                self.member_forwarded.token.value()
            )),
        }
    }

    /// Converts raw `ImplMap` entry to owned structure with resolved references.
    ///
    /// This method processes the raw table entry by resolving all coded indexes
    /// and heap references, creating an [`ImplMap`] instance with owned data
    /// suitable for runtime use and further processing.
    ///
    /// # Arguments
    /// * `get_ref` - Closure to resolve coded indexes to type references
    /// * `strings` - String heap for resolving import function names
    /// * `modules` - `ModuleRef` map for resolving target library references
    ///
    /// # Returns
    /// * `Ok(ImplMapRc)` - Successfully converted owned `ImplMap` structure
    /// * `Err(_)` - Reference resolution failed or invalid data
    ///
    /// # Errors
    /// - Invalid `member_forwarded` coded index or weak reference upgrade failure
    /// - String heap lookup fails for import name
    /// - `ModuleRef` reference cannot be resolved
    /// - Non-MethodDef reference in `member_forwarded` (unsupported)
    pub fn to_owned<F>(
        &self,
        get_ref: F,
        strings: &Strings,
        modules: &ModuleRefMap,
    ) -> Result<ImplMapRc>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let member_forwarded = match get_ref(&self.member_forwarded) {
            CilTypeReference::MethodDef(method_def) => match method_def.upgrade() {
                Some(method) => {
                    method
                        .flags_pinvoke
                        .store(self.mapping_flags, Ordering::Relaxed);
                    method
                }
                None => {
                    return Err(malformed_error!(
                        "Failed to upgrade MethodDef weak reference - {}",
                        self.member_forwarded.token.value()
                    ))
                }
            },
            _ => {
                return Err(malformed_error!(
                    "Invalid member_forwarded token - {}",
                    self.member_forwarded.token.value()
                ))
            }
        };

        Ok(Arc::new(ImplMap {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            mapping_flags: self.mapping_flags,
            member_forwarded,
            import_name: strings.get_shared(self.import_name as usize)?,
            import_scope: match modules.get(&Token::new(self.import_scope | 0x1A00_0000)) {
                Some(module_ref) => module_ref.value().clone(),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve import_scope token - {}",
                        self.import_scope | 0x1A00_0000
                    ))
                }
            },
        }))
    }
}

impl TableRow for ImplMapRaw {
    /// Calculate the byte size of an ImplMap table row
    ///
    /// Returns the total size of one row in the ImplMap table, including:
    /// - mapping_flags: 2 bytes
    /// - member_forwarded: 2 or 4 bytes (MemberForwarded coded index)
    /// - import_name: 2 or 4 bytes (String heap index)
    /// - import_scope: 2 or 4 bytes (ModuleRef table index)
    ///
    /// The index sizes depend on the metadata table and heap requirements.
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* mapping_flags */    2u8
            /* member_forwarded */ .saturating_add(sizes.coded_index_bytes(CodedIndexType::MemberForwarded))
            /* import_name */      .saturating_add(sizes.str_bytes())
            /* import_scope */     .saturating_add(sizes.table_index_bytes(TableId::ModuleRef))

        )
    }
}

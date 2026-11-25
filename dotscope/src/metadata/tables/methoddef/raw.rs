//! Raw `MethodDef` table structure with unresolved indexes and heap references.
//!
//! This module provides the [`crate::metadata::tables::methoddef::raw::MethodDefRaw`] struct, which represents method definitions
//! as stored in the metadata stream. The structure contains unresolved indexes
//! and heap references that require processing to establish complete method information
//! with parameter metadata and signature details.
//!
//! # Purpose
//! [`crate::metadata::tables::methoddef::raw::MethodDefRaw`] serves as the direct representation of `MethodDef` table entries from the
//! binary metadata stream, before parameter resolution and signature parsing. This raw format
//! is processed during metadata loading to create [`crate::metadata::method::Method`] instances with resolved
//! parameters and complete method implementation information.
//!
//! # Architecture
//!
//! The raw implementation provides the foundation for method definition parsing:
//! - **Unresolved References**: Contains raw heap indices and table references
//! - **Memory Efficiency**: Minimal footprint during initial parsing phases
//! - **Binary Format**: Direct representation of ECMA-335 table structure
//! - **Batch Processing**: Optimized for parsing multiple method entries efficiently
//!
//! # Binary Format
//!
//! Each `MethodDef` table row follows the ECMA-335 §22.26 specification:
//!
//! ```text
//! Offset | Size    | Field      | Description
//! -------|---------|------------|--------------------------------------------
//! 0x00   | 4 bytes | RVA        | Relative virtual address of implementation
//! 0x04   | 2 bytes | ImplFlags  | Method implementation attributes
//! 0x06   | 2 bytes | Flags      | Method attributes and access modifiers
//! 0x08   | 2-4     | Name       | String heap index for method name
//! 0x0A   | 2-4     | Signature  | Blob heap index for method signature
//! 0x0C   | 2-4     | ParamList  | Index into Param table for first parameter
//! ```
//!
//! # Processing Pipeline
//!
//! 1. **Binary Parsing**: Raw entries are read from metadata tables stream
//! 2. **Validation**: RVA, flags, and indices are validated for consistency
//! 3. **Resolution**: Heap indices are resolved to actual data values
//! 4. **Parameter Processing**: Parameter ranges are calculated and resolved
//! 5. **Signature Parsing**: Method signatures are parsed from blob heap
//! 6. **Conversion**: Raw entries are converted to owned method representations
//!
//! # Thread Safety
//!
//! All types in this module are thread-safe for concurrent read access:
//! - [`crate::metadata::tables::methoddef::raw::MethodDefRaw`] is [`std::marker::Send`] and [`std::marker::Sync`]
//! - Raw parsing operations can be performed concurrently
//! - Conversion methods are thread-safe with proper heap synchronization
//! - No shared mutable state during parsing operations
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables::methoddef`] - Method definition module and owned representations
//! - [`crate::metadata::tables::param`] - Parameter table for method parameter resolution
//! - [`crate::metadata::method`] - Method definition types and containers
//! - [`crate::metadata::signatures`] - Method signature parsing and validation

use std::sync::{atomic::AtomicU32, Arc, OnceLock};

use crate::{
    metadata::{
        method::{
            Method, MethodAccessFlags, MethodImplCodeType, MethodImplManagement, MethodImplOptions,
            MethodModifiers, MethodRc, MethodVtableFlags,
        },
        signatures::parse_method_signature,
        streams::{Blob, Strings},
        tables::{MemberRanges, ParamList, ParamMap, ParamPtrMap, TableId, TableInfoRef, TableRow},
        token::Token,
    },
    utils::{LazyList, RowList},
    Result,
};

/// Raw `MethodDef` table entry with unresolved indexes and heap references.
///
/// This structure represents a method definition as stored directly in the metadata stream.
/// All references are unresolved indexes or heap offsets that require processing during
/// metadata loading to establish complete method information with parameter metadata
/// and implementation details.
///
/// # Table Structure (ECMA-335 §22.26)
/// | Column | Size | Description |
/// |--------|------|-------------|
/// | RVA | 4 bytes | Relative virtual address of method implementation |
/// | `ImplFlags` | 2 bytes | Method implementation attributes |
/// | Flags | 2 bytes | Method attributes and access modifiers |
/// | Name | String index | Method name identifier |
/// | Signature | Blob index | Method signature (calling convention, parameters, return type) |
/// | `ParamList` | Param index | First parameter in the parameter list |
///
/// # Implementation Attributes (`ImplFlags`)
/// The `impl_flags` field contains method implementation characteristics:
/// - **Code type**: IL, native, OPTIL, or runtime implementation
/// - **Management**: Managed, unmanaged, or mixed execution model
/// - **Implementation**: Forward reference, synchronized, or no inlining flags
/// - **Security**: Security critical or transparent method marking
///
/// # Method Attributes (Flags)
/// The `flags` field contains method access and behavior modifiers:
/// - **Access**: Private, public, protected, internal visibility levels
/// - **Virtual dispatch**: Virtual, abstract, final, override, or new slot semantics
/// - **Special methods**: Constructor, property accessor, event handler, or operator
/// - **Calling convention**: Static, instance, or vararg method calling patterns
///
/// # Parameter Resolution
/// The `param_list` field provides access to method parameters:
/// - **Parameter range**: Contiguous range in the Param table for this method
/// - **Return parameter**: Special parameter at sequence 0 for return type information
/// - **Parameter metadata**: Names, types, default values, and custom attributes
/// - **Indirect access**: Optional `ParamPtr` table for parameter pointer indirection
///
/// # RVA and Implementation
///
/// The `rva` field specifies method implementation location:
/// - **Zero RVA**: Abstract methods, interface methods, or extern methods without implementation
/// - **Non-zero RVA**: Concrete methods with IL code or native implementation at specified address
/// - **Implementation Type**: Determined by combination of RVA and implementation flags
///
/// # Usage Patterns
///
/// ```no_run
/// use dotscope::metadata::tables::MethodDefRaw;
/// use dotscope::metadata::streams::{Strings, Blob};
///
/// # fn process_method_entry(raw_entry: &MethodDefRaw, strings: &Strings, blob: &Blob) -> dotscope::Result<()> {
/// // Check method implementation type
/// if raw_entry.rva == 0 {
///     println!("Abstract or interface method: {}", raw_entry.rid);
/// } else {
///     println!("Concrete method at RVA: 0x{:08X}", raw_entry.rva);
/// }
///
/// // Access method name
/// let method_name = strings.get(raw_entry.name as usize)?;
/// println!("Method name: {}", method_name);
///
/// // Access method signature
/// let signature_data = blob.get(raw_entry.signature as usize)?;
/// println!("Signature has {} bytes", signature_data.len());
/// # Ok(())
/// # }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// [`MethodDefRaw`] is [`std::marker::Send`] and [`std::marker::Sync`] as it contains only primitive data types.
/// Instances can be safely shared across threads and accessed concurrently without synchronization.
#[derive(Clone, Debug)]
pub struct MethodDefRaw {
    /// Row identifier within the `MethodDef` table.
    ///
    /// Unique identifier for this method definition entry, used for internal
    /// table management and token generation.
    pub rid: u32,

    /// Metadata token for this `MethodDef` entry (`TableId` 0x06).
    ///
    /// Computed as `0x06000000 | rid` to create the full token value
    /// for referencing this method from other metadata structures.
    pub token: Token,

    /// Byte offset of this entry within the raw table data.
    ///
    /// Used for efficient table navigation and binary metadata processing.
    pub offset: usize,

    /// Relative virtual address of the method implementation.
    ///
    /// Points to the method's IL code or native implementation within the PE file.
    /// A value of 0 indicates an abstract method, interface method, or extern method
    /// without implementation in the current assembly.
    pub rva: u32,

    /// Method implementation attributes bitmask.
    ///
    /// Contains flags controlling method implementation characteristics including
    /// code type (IL/native), management model (managed/unmanaged), and special
    /// implementation features (synchronized, no inlining, etc.).
    pub impl_flags: u32,

    /// Method attributes and access modifiers bitmask.
    ///
    /// Contains flags controlling method visibility, virtual dispatch behavior,
    /// special method types, and calling conventions. Used for access control
    /// and method resolution during compilation and runtime.
    pub flags: u32,

    /// String heap index for the method name.
    ///
    /// References the method identifier name in the string heap. For constructors,
    /// this is typically ".ctor" (instance) or ".cctor" (static type initializer).
    pub name: u32,

    /// Blob heap index for the method signature.
    ///
    /// References signature data in the blob heap describing calling convention,
    /// parameter types, return type, and generic type parameters. Must be parsed
    /// according to method signature format specifications.
    pub signature: u32,

    /// Index into the Param table for the first parameter.
    ///
    /// Specifies the starting position of this method's parameters in the Param table.
    /// Parameter lists are contiguous ranges ending at the next method's `param_list`
    /// or the end of the table. A value of 0 indicates no parameters.
    pub param_list: u32,
}

impl MethodDefRaw {
    /// Converts a `MethodDefRaw` entry into a Method with resolved parameters and parsed signature.
    ///
    /// This method performs complete method definition resolution, including parameter
    /// range calculation, signature parsing, and method attribute processing. The resulting
    /// owned structure provides complete method information for invocation, reflection,
    /// and type system integration.
    ///
    /// # Arguments
    /// * `strings` - The string heap for resolving method names
    /// * `blob` - The blob heap for signature data retrieval
    /// * `params_map` - Collection of all Param entries for parameter resolution
    /// * `param_ptr_map` - Collection of `ParamPtr` entries for indirection (if present)
    /// * `param_ranges` - The normalized `ParamList` runs of the whole `MethodDef` table
    ///   ([`TablesHeader::member_ranges`](crate::metadata::streams::TablesHeader::member_ranges)
    ///   with [`MemberList::MethodDefParams`](crate::metadata::tables::MemberList::MethodDefParams)),
    ///   which also decide whether `param_ptr_map` is consulted
    ///
    /// # Returns
    /// * `Ok(MethodRc)` - Successfully resolved method with complete parameter metadata
    /// * `Err(_)` - If signature parsing, parameter resolution, or name retrieval fails
    ///
    /// # Errors
    ///
    /// Returns an error if signature parsing or name retrieval fails, or if a position in the
    /// method's parameter run names a `ParamPtr` row or a parameter that is not loaded (the run
    /// itself is always in range: the ranges are normalized).
    pub fn to_owned(
        &self,
        strings: &Strings,
        blob: &Blob,
        params_map: &ParamMap,
        param_ptr_map: &ParamPtrMap,
        param_ranges: &MemberRanges,
    ) -> Result<MethodRc> {
        let signature = parse_method_signature(blob.get(self.signature as usize)?)?;

        let type_params = ParamList::new();
        for param in param_ranges.members(self.rid, param_ptr_map, |ptr| ptr.param, params_map) {
            _ = type_params.push(param?);
        }
        Ok(Arc::new(Method {
            rid: self.rid,
            token: self.token,
            meta_offset: self.offset,
            name: strings.get_shared(self.name as usize)?,
            impl_code_type: MethodImplCodeType::from_impl_flags(self.impl_flags),
            impl_management: MethodImplManagement::from_impl_flags(self.impl_flags),
            impl_options: MethodImplOptions::from_impl_flags(self.impl_flags),
            flags_access: MethodAccessFlags::from_method_flags(self.flags),
            flags_vtable: MethodVtableFlags::from_method_flags(self.flags),
            flags_modifiers: MethodModifiers::from_method_flags(self.flags),
            flags_pinvoke: AtomicU32::new(0),
            params: type_params,
            generic_params: Default::default(),
            generic_args: LazyList::new(),
            signature,
            rva: if self.rva == 0 { None } else { Some(self.rva) },
            body: OnceLock::new(),
            local_vars: LazyList::new(),
            overrides: Default::default(),
            interface_impls: Default::default(),
            security: RowList::new(),
            blocks: OnceLock::new(),
            custom_attributes: Default::default(),
            declaring_type: OnceLock::new(),
        }))
    }

    /// Apply a `MethodDefRaw` entry to update related metadata structures.
    ///
    /// `MethodDef` entries define methods within types. They are associated with their parent
    /// types but don't themselves modify other metadata during the dual variant resolution phase.
    /// Method-specific metadata (P/Invoke info, generic parameters, etc.) is resolved separately.
    ///
    /// # Errors
    /// Always returns `Ok(())` as `MethodDef` entries don't modify other tables directly.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl TableRow for MethodDefRaw {
    /// Calculate the byte size of a MethodDef table row
    ///
    /// Computes the total size based on fixed-size fields plus variable-size heap and table indexes.
    /// The size depends on whether the metadata uses 2-byte or 4-byte indexes.
    ///
    /// # Row Layout (ECMA-335 §II.22.26)
    /// - `rva`: 4 bytes (fixed)
    /// - `impl_flags`: 2 bytes (fixed)
    /// - `flags`: 2 bytes (fixed)
    /// - `name`: 2 or 4 bytes (string heap index)
    /// - `signature`: 2 or 4 bytes (blob heap index)
    /// - `param_list`: 2 or 4 bytes (Param table index)
    ///
    /// # Arguments
    /// * `sizes` - Table sizing information for heap and table index widths
    ///
    /// # Returns
    /// Total byte size of one MethodDef table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* rva */        4u8
            /* impl_flags */ .saturating_add(2)
            /* flags */      .saturating_add(2)
            /* name */       .saturating_add(sizes.str_bytes())
            /* signature */  .saturating_add(sizes.blob_bytes())
            /* param_list */ .saturating_add(sizes.table_index_bytes(TableId::Param))

        )
    }
}

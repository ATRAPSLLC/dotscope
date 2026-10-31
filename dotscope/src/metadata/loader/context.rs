//! Centralized metadata loading context for .NET assembly processing.
//!
//! This module provides the [`LoaderContext`] structure that serves as the central hub
//! for all metadata table maps during the assembly loading process. It coordinates
//! parallel loading operations and provides unified access to metadata streams,
//! tables, and registries throughout the loading pipeline.
//!
//! # Loading Architecture
//!
//! The context follows a specific lifecycle:
//! 1. **Creation**: Built in internal data structures from file
//! 2. **Population**: Passed to parallel loaders via `execute_loaders_in_parallel`
//! 3. **Resolution**: Provides coded index resolution and cross-table lookups
//! 4. **Cleanup**: Automatically dropped after loading completes
//!
//! # Key Responsibilities
//!
//! - **Stream Access**: Provides unified access to metadata streams (strings, blobs, etc.)
//! - **Table Management**: Holds maps for all metadata tables during loading
//! - **Cross-References**: Resolves coded indices between different table types
//! - **Type Registry**: Coordinates with the central type system
//! - **Import/Export**: Manages assembly dependency relationships
//!
//! # Parallel Loading Support
//!
//! The context is designed for concurrent access during parallel loading:
//! - Reference-counted data structures for shared access
//! - Thread-safe maps and registries
//! - Immutable stream references
//! - Lock-based coordination for critical sections
//!
//! # Examples
//!
//! The loaders show it in use: `CustomAttributeLoader` resolves each attribute's parent
//! and constructor with [`LoaderContext::get_ref`] (`metadata/tables/customattribute/loader.rs`).
//!
//! # Memory Management
//!
//! The context uses careful memory management strategies:
//! - **Borrowed References**: Most data is borrowed from the parent CilObject
//! - **Reference Counting**: Shared data uses Arc for safe concurrent access
//! - **Lazy Initialization**: Some tables use OnceLock for deferred loading
//! - **Scoped Lifetime**: Context is dropped immediately after loading
//!
//! # Thread Safety
//!
//! All components in this module are designed for safe concurrent access during parallel loading.
//! The internal loader context contains thread-safe data structures and
//! is [`std::marker::Send`] and [`std::marker::Sync`], enabling efficient parallel processing
//! of metadata tables across multiple threads.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::loader::data`] - Assembly data loading and context creation
//! - [`crate::metadata::typesystem`] - Type registry and reference resolution
//! - [`crate::metadata::tables`] - All metadata table types and coded index resolution
//! - [`crate::metadata::streams`] - Metadata stream access and heap operations

use std::{
    fmt::Display,
    result::Result as StdResult,
    sync::{Arc, OnceLock},
};

use crate::{
    file::File,
    metadata::{
        cor20header::Cor20Header,
        diagnostics::{Diagnostic, DiagnosticCategory, DiagnosticSeverity, Diagnostics},
        exports::Exports,
        imports::Imports,
        method::MethodMap,
        pdb::PortablePdb,
        resources::Resources,
        root::Root,
        streams::{Blob, Guid, Strings, TablesHeader, UserStrings},
        tables::{
            AssemblyOsRc, AssemblyProcessorRc, AssemblyRc, AssemblyRefMap, AssemblyRefOsMap,
            AssemblyRefProcessorMap, ClassLayoutMap, CodedIndex, ConstantMap, CustomAttributeMap,
            DeclSecurityMap, EncLogMap, EncMapMap, EventMap, EventMapEntryMap, EventPtrMap,
            FieldLayoutMap, FieldMap, FieldMarshalMap, FieldPtrMap, FieldRVAMap, FileMap,
            GenericParamConstraintMap, GenericParamMap, InterfaceImplMap, MemberRefMap,
            MethodImplMap, MethodPtrMap, MethodSemanticsMap, MethodSpecMap, ModuleRc, ModuleRefMap,
            NestedClassMap, ParamMap, ParamPtrMap, PropertyMap, PropertyMapEntryMap,
            PropertyPtrMap, RowReadable, StandAloneSigMap, TableId, TypeSpecMap,
        },
        typesystem::{CilTypeReference, TypeRegistry},
    },
    Result,
};

/// Centralized context for metadata table maps during assembly loading.
///
/// This structure serves as the central coordination point for all metadata loading
/// operations in a .NET assembly. It provides unified access to metadata streams,
/// table maps, and cross-reference resolution capabilities required by parallel
/// loading operations.
///
/// # Lifecycle Management
///
/// The context follows a specific lifecycle pattern:
/// 1. **Initialization**: Created with references to parsed metadata streams
/// 2. **Population**: Parallel loaders populate table maps via `to_owned()` conversions
/// 3. **Resolution**: Cross-table references resolved via [`get_ref`](Self::get_ref) method
/// 4. **Application**: Loaders call `apply()` methods to build semantic relationships
/// 5. **Disposal**: Context automatically dropped after loading completes
///
/// # Data Organization
///
/// **Core Metadata**: Assembly header, streams, and basic structures
/// **Table Maps**: Concurrent containers for all metadata table types
/// **Registries**: Type system and import/export management
/// **References**: Cross-table relationship resolution
///
/// # Thread Safety
///
/// [`LoaderContext`] is [`std::marker::Send`] and [`std::marker::Sync`], designed for safe concurrent access:
/// - All maps use thread-safe data structures ([`crossbeam_skiplist::SkipMap`], [`dashmap::DashMap`])
/// - Metadata streams are immutable references
/// - Registries provide atomic operations
/// - Critical sections use [`std::sync::Arc`]<[`std::sync::OnceLock`]> for coordination
/// - Reference-counted data enables safe sharing across parallel loaders
///
/// # Examples
///
/// Every table loader receives one; `CustomAttributeLoader`
/// (`metadata/tables/customattribute/loader.rs`) reads its maps and resolves coded indices
/// through it.
pub(crate) struct LoaderContext<'a> {
    // Core Assembly Data
    /// Input file reference for the assembly being loaded.
    pub input: Arc<File>,
    /// Raw binary data of the assembly file.
    pub data: &'a [u8],
    /// CLR 2.0 header containing metadata root and stream information.
    pub header: &'a Cor20Header,
    /// Metadata root header with stream definitions and signatures.
    pub header_root: &'a Root,
    /// Diagnostics collection for reporting loading issues.
    pub diagnostics: &'a Arc<Diagnostics>,
    /// Whether to continue loading on errors (lenient mode) or abort (strict mode).
    /// Default is false (strict mode) - errors will abort loading.
    /// When true, errors are logged to diagnostics and loading continues.
    pub lenient: bool,

    // Metadata Streams
    /// Tables stream containing all metadata table definitions.
    pub meta: Option<&'a TablesHeader<'a>>,
    /// String heap containing UTF-8 encoded names and identifiers.
    pub strings: Option<&'a Strings<'a>>,
    /// User string heap containing literal string constants.
    pub userstrings: Option<&'a UserStrings<'a>>,
    /// GUID heap containing unique identifiers for types and assemblies.
    pub guids: Option<&'a Guid<'a>>,
    /// Blob heap containing binary data (signatures, custom attributes, etc.).
    pub blobs: Option<&'a Blob<'a>>,

    // Assembly and Module Tables
    /// Assembly definition (single entry per assembly).
    pub assembly: &'a OnceLock<AssemblyRc>,
    /// Assembly operating system information.
    pub assembly_os: &'a OnceLock<AssemblyOsRc>,
    /// Assembly processor architecture information.
    pub assembly_processor: &'a OnceLock<AssemblyProcessorRc>,
    /// Assembly references to external assemblies.
    pub assembly_ref: &'a AssemblyRefMap,
    /// Operating system information for assembly references.
    pub assembly_ref_os: AssemblyRefOsMap,
    /// Processor information for assembly references.
    pub assembly_ref_processor: AssemblyRefProcessorMap,
    /// Module definition (primary module of the assembly).
    pub module: &'a OnceLock<ModuleRc>,
    /// Module references to external modules.
    pub module_ref: &'a ModuleRefMap,

    // Type System Tables
    /// Type specifications for instantiated generic types.
    pub type_spec: TypeSpecMap,

    // Method and Field Tables
    /// Method definitions in the assembly.
    pub method_def: &'a MethodMap,
    /// Method implementations for interface/virtual methods.
    pub method_impl: MethodImplMap,
    /// Method semantics (property getters/setters, event handlers).
    pub method_semantics: MethodSemanticsMap,
    /// Method specifications for generic method instantiations.
    pub method_spec: &'a MethodSpecMap,
    /// Field definitions in types.
    pub field: &'a FieldMap,
    /// Field pointer indirection table.
    pub field_ptr: FieldPtrMap,
    /// Method pointer indirection table.
    pub method_ptr: MethodPtrMap,
    /// Field layout information for explicit layout types.
    pub field_layout: FieldLayoutMap,
    /// Field marshalling information for interop.
    pub field_marshal: FieldMarshalMap,
    /// Field relative virtual addresses for initialized data.
    pub field_rva: FieldRVAMap,

    // Edit-and-Continue Tables
    /// Edit-and-Continue log entries tracking debugging modifications.
    pub enc_log: EncLogMap,
    /// Edit-and-Continue token mapping for debugging scenarios.
    pub enc_map: EncMapMap,

    // Portable PDB
    /// The Portable PDB the debug-table loaders read and fill, when the assembly has one.
    pub pdb: Option<PdbSource<'a>>,

    // Parameter and Generic Tables
    /// Parameter definitions for methods.
    pub param: ParamMap,
    /// Parameter pointer indirection table.
    pub param_ptr: ParamPtrMap,
    /// Generic parameter definitions for generic types and methods.
    pub generic_param: GenericParamMap,
    /// Constraints on generic parameters.
    pub generic_param_constraint: GenericParamConstraintMap,

    // Property and Event Tables
    /// Property definitions in types.
    pub property: PropertyMap,
    /// Property pointer indirection table.
    pub property_ptr: PropertyPtrMap,
    /// Property map linking types to their properties.
    pub property_map: PropertyMapEntryMap,
    /// Event definitions in types.
    pub event: EventMap,
    /// Event pointer indirection table.
    pub event_ptr: EventPtrMap,
    /// Event map linking types to their events.
    pub event_map: EventMapEntryMap,

    // Reference and Relationship Tables
    /// Member references to external methods and fields.
    pub member_ref: &'a MemberRefMap,
    /// Class layout information for explicit layout types.
    pub class_layout: ClassLayoutMap,
    /// Nested class relationships.
    pub nested_class: NestedClassMap,
    /// Interface implementation relationships.
    pub interface_impl: InterfaceImplMap,

    // Metadata and Security Tables
    /// Constant values for fields, parameters, and properties.
    pub constant: ConstantMap,
    /// Custom attribute definitions.
    pub custom_attribute: &'a CustomAttributeMap,
    /// Declarative security attributes.
    pub decl_security: &'a DeclSecurityMap,
    /// File definitions for multi-file assemblies.
    pub file: &'a FileMap,
    /// Exported type definitions.
    pub exported_type: &'a Exports,
    /// Standalone signature definitions.
    pub standalone_sig: StandAloneSigMap,

    // High-Level Registries
    /// Import tracking for external dependencies.
    pub imports: &'a Imports,
    /// Resource management for embedded resources.
    pub resources: &'a Resources,
    /// Central type registry for all loaded types.
    pub types: &'a Arc<TypeRegistry>,
}

/// The metadata the Portable PDB's tables are read from, and the PDB they fill.
///
/// For debug tables in the image's own metadata these are the image's tables and heaps; for
/// an embedded or standalone PDB, the PDB's own. Either way their columns index the image's
/// tables, which the loaders resolve through the [`LoaderContext`].
pub(crate) struct PdbSource<'a> {
    /// The tables stream holding the debug tables
    pub meta: Option<&'a TablesHeader<'a>>,
    /// The `#Strings` heap
    pub strings: Option<&'a Strings<'a>>,
    /// The `#Blob` heap
    pub blobs: Option<&'a Blob<'a>>,
    /// The `#GUID` heap
    pub guids: Option<&'a Guid<'a>>,
    /// Whether a malformed row is a diagnostic rather than an error. The runtime never reads
    /// debug information to load an assembly, so the PDB found in the image is always read
    /// leniently; a standalone PDB follows the load's mode.
    pub lenient: bool,
    /// The PDB the loaders fill
    pub target: &'a PortablePdb,
}

impl LoaderContext<'_> {
    /// Resolve a coded index to a [`crate::metadata::typesystem::CilTypeReference`].
    ///
    /// This method provides unified coded index resolution across all metadata tables
    /// during the loading process. It uses the [`crate::metadata::tables::CodedIndex`]'s table identifier
    /// and token to look up the corresponding entity in the appropriate table map,
    /// then converts it to the correct [`crate::metadata::typesystem::CilTypeReference`] variant.
    ///
    /// # Supported Tables
    ///
    /// The method handles resolution for all major metadata table types:
    /// - **Type Tables**: `TypeDef`, `TypeRef`, `TypeSpec`
    /// - **Method Tables**: `MethodDef`, `MemberRef`, `MethodSpec`  
    /// - **Field/Property Tables**: `Field`, `Property`, `Param`, `Event`
    /// - **Assembly Tables**: `Assembly`, `AssemblyRef`, Module, `ModuleRef`
    /// - **Generic Tables**: `GenericParam`, `GenericParamConstraint`
    /// - **Other Tables**: `File`, `ExportedType`, `StandAloneSig`, `DeclSecurity`, `InterfaceImpl`
    ///
    /// # Resolution Strategy
    ///
    /// 1. **Table Identification**: Uses the coded index's `tag` field to determine target table
    /// 2. **Token Lookup**: Searches the appropriate table map using the `token` field
    /// 3. **Reference Creation**: Converts the found entity to the correct reference type
    /// 4. **Fallback Handling**: Returns [`crate::metadata::typesystem::CilTypeReference::None`] for unresolved references
    ///
    /// # Arguments
    /// * `coded_index` - The [`crate::metadata::tables::CodedIndex`] containing table ID and token to resolve
    ///
    /// # Returns
    /// The corresponding [`crate::metadata::typesystem::CilTypeReference`] variant, or
    /// [`crate::metadata::typesystem::CilTypeReference::None`] if the coded index cannot be resolved.
    ///
    /// # Examples
    ///
    /// `CustomAttributeLoader` (`metadata/tables/customattribute/loader.rs`) resolves each
    /// attribute's parent and constructor through it.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads during parallel loading.
    pub fn get_ref(&self, coded_index: &CodedIndex) -> CilTypeReference {
        match coded_index.tag {
            TableId::TypeDef => {
                if let Some(type_def) = self.types.get(&coded_index.token) {
                    CilTypeReference::TypeDef(type_def.into())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::TypeRef => {
                if let Some(type_ref) = self.types.get(&coded_index.token) {
                    CilTypeReference::TypeRef(type_ref.into())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::TypeSpec => {
                if let Some(type_spec) = self.types.get(&coded_index.token) {
                    CilTypeReference::TypeSpec(type_spec.into())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::MethodDef => {
                if let Some(method_def) = self.method_def.get(&coded_index.token) {
                    CilTypeReference::MethodDef(method_def.value().clone().into())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::MemberRef => {
                if let Some(member_ref) = self.member_ref.get(&coded_index.token) {
                    CilTypeReference::MemberRef(member_ref.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::Field => {
                if let Some(field) = self.field.get(&coded_index.token) {
                    CilTypeReference::Field(field.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::Param => {
                if let Some(param) = self.param.get(&coded_index.token) {
                    CilTypeReference::Param(param.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::Property => {
                if let Some(property) = self.property.get(&coded_index.token) {
                    CilTypeReference::Property(property.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::Event => {
                if let Some(event) = self.event.get(&coded_index.token) {
                    CilTypeReference::Event(event.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::InterfaceImpl => {
                if let Some(interface_impl) = self.interface_impl.get(&coded_index.token) {
                    CilTypeReference::InterfaceImpl(interface_impl.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::Module => {
                if let Some(module) = self.module.get() {
                    CilTypeReference::Module(module.clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::ModuleRef => {
                if let Some(module_ref) = self.module_ref.get(&coded_index.token) {
                    CilTypeReference::ModuleRef(module_ref.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::Assembly => {
                if let Some(assembly) = self.assembly.get() {
                    CilTypeReference::Assembly(assembly.clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::AssemblyRef => {
                if let Some(assembly_ref) = self.assembly_ref.get(&coded_index.token) {
                    CilTypeReference::AssemblyRef(assembly_ref.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::File => {
                if let Some(file) = self.file.get(&coded_index.token) {
                    CilTypeReference::File(file.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::ExportedType => {
                if let Some(exported_type) = self.exported_type.get(&coded_index.token) {
                    CilTypeReference::ExportedType(exported_type.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::GenericParam => {
                if let Some(generic_param) = self.generic_param.get(&coded_index.token) {
                    CilTypeReference::GenericParam(generic_param.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::GenericParamConstraint => {
                if let Some(constraint) = self.generic_param_constraint.get(&coded_index.token) {
                    CilTypeReference::GenericParamConstraint(constraint.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::MethodSpec => {
                if let Some(method_spec) = self.method_spec.get(&coded_index.token) {
                    CilTypeReference::MethodSpec(method_spec.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::DeclSecurity => {
                if let Some(decl_security) = self.decl_security.get(&coded_index.token) {
                    CilTypeReference::DeclSecurity(decl_security.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::StandAloneSig => {
                if let Some(standalone_sig) = self.standalone_sig.get(&coded_index.token) {
                    CilTypeReference::StandAloneSig(standalone_sig.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            _ => CilTypeReference::None,
        }
    }

    /// Handles a result according to the lenient/strict loading mode.
    ///
    /// In strict mode (default), errors are propagated immediately.
    /// In lenient mode, errors are logged to diagnostics and `Ok(None)` is returned
    /// to allow loading to continue.
    ///
    /// # Arguments
    ///
    /// * `result` - The result of a loading operation
    /// * `category` - The diagnostic category for error logging
    /// * `context_msg` - A closure that produces a context message (only called on error)
    ///
    /// # Returns
    ///
    /// * `Ok(Some(value))` - Operation succeeded
    /// * `Ok(None)` - Operation failed but we're in lenient mode
    /// * `Err(e)` - Operation failed in strict mode
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dotscope::metadata::diagnostics::DiagnosticCategory;
    ///
    /// let result = row.to_owned(strings, blob);
    /// if let Some(owned) = context.handle_result(
    ///     result,
    ///     DiagnosticCategory::Table,
    ///     || format!("token 0x{:08x}", row.token.value())
    /// )? {
    ///     // Use owned value
    /// }
    /// ```
    pub fn handle_result<T, E: Display, F: FnOnce() -> String>(
        &self,
        result: StdResult<T, E>,
        category: DiagnosticCategory,
        context_msg: F,
    ) -> Result<Option<T>> {
        self.handle_result_in(self.lenient, result, category, context_msg)
    }

    /// [`handle_result`](Self::handle_result) in the mode `lenient` rather than the load's,
    /// for metadata read in a mode of its own (a [`PdbSource`]).
    pub fn handle_result_in<T, E: Display, F: FnOnce() -> String>(
        &self,
        lenient: bool,
        result: StdResult<T, E>,
        category: DiagnosticCategory,
        context_msg: F,
    ) -> Result<Option<T>> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(e) => {
                let msg = context_msg();
                if lenient {
                    self.diagnostics
                        .warning(category, format!("Failed to load {msg}: {e}"));
                    Ok(None)
                } else {
                    Err(malformed_error!("Failed to load {}: {}", msg, e))
                }
            }
        }
    }

    /// Handles a *row-parse* failure according to the lenient/strict loading mode.
    ///
    /// The counterpart to [`handle_result`](Self::handle_result) for the one failure that
    /// happens before there is anything to build a message from. Every loader routes the
    /// failures it can describe - `to_owned`, reference resolution - through `handle_result`
    /// with a message keyed on `row.token`. A row that failed to *parse* has no token, so it
    /// cannot use that path, and the natural `let row = row?;` propagates straight out of
    /// `load()` and aborts the whole [`CilObject`](crate::CilObject) load. That defeats
    /// [`lenient`](Self::lenient) for exactly the malformed input the flag exists to tolerate:
    /// one truncated row at the end of one table would take the file down.
    ///
    /// Identity comes from the table id and RID instead, recorded structurally on the
    /// diagnostic via [`Diagnostic::with_table_row`] so consumers can locate the row without
    /// parsing the message.
    ///
    /// # Arguments
    ///
    /// * `row` - The row-parse result, as yielded by the table iterators
    /// * `index` - The row's 0-based position in the iteration. The table iterators are
    ///   range-based and read each row at an offset derived from its own RID, so nothing is
    ///   dropped on a parse failure and `index + 1` is the true RID - unlike a filtered
    ///   sequence, where position stops tracking RID.
    ///
    /// The table is taken from [`RowReadable::TABLE_ID`], so it cannot drift from the row
    /// type being loaded.
    ///
    /// # Returns
    ///
    /// * `Ok(Some(row))` - The row parsed
    /// * `Ok(None)` - The row did not parse and we are in lenient mode; skip it
    /// * `Err(e)` - The row did not parse and we are in strict mode
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Malformed`] when a row fails to parse in strict mode.
    pub fn handle_row<T: RowReadable>(&self, row: Result<T>, index: usize) -> Result<Option<T>> {
        self.handle_row_in(self.lenient, row, index)
    }

    /// [`handle_row`](Self::handle_row) in the mode `lenient` rather than the load's, for
    /// metadata read in a mode of its own (a [`PdbSource`]).
    pub fn handle_row_in<T: RowReadable>(
        &self,
        lenient: bool,
        row: Result<T>,
        index: usize,
    ) -> Result<Option<T>> {
        match row {
            Ok(row) => Ok(Some(row)),
            Err(e) => {
                let table = T::TABLE_ID;
                let rid = u32::try_from(index).unwrap_or(u32::MAX).saturating_add(1);
                if lenient {
                    self.diagnostics.push(
                        Diagnostic::new(
                            DiagnosticSeverity::Warning,
                            DiagnosticCategory::Table,
                            format!("Failed to parse {table:?} row {rid}: {e}"),
                        )
                        .with_table_row(table as u8, rid),
                    );
                    Ok(None)
                } else {
                    Err(malformed_error!(
                        "Failed to parse {:?} row {}: {}",
                        table,
                        rid,
                        e
                    ))
                }
            }
        }
    }

    /// Handles an error according to the lenient/strict loading mode.
    ///
    /// In strict mode (default), errors are propagated immediately.
    /// In lenient mode, errors are logged to diagnostics and `Ok(())` is returned.
    ///
    /// # Arguments
    ///
    /// * `result` - The result of an operation that may fail
    /// * `category` - The diagnostic category for error logging
    /// * `context_msg` - A closure that produces a context message (only called on error)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Operation succeeded or failed in lenient mode
    /// * `Err(e)` - Operation failed in strict mode
    pub fn handle_error<E: Display, F: FnOnce() -> String>(
        &self,
        result: StdResult<(), E>,
        category: DiagnosticCategory,
        context_msg: F,
    ) -> Result<()> {
        match result {
            Ok(()) => Ok(()),
            Err(e) => {
                let msg = context_msg();
                if self.lenient {
                    self.diagnostics
                        .warning(category, format!("Failed to process {msg}: {e}"));
                    Ok(())
                } else {
                    Err(malformed_error!("Failed to process {}: {}", msg, e))
                }
            }
        }
    }
}

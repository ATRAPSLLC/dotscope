//! Core data structure for .NET assembly metadata storage and processing.
//!
//! This module contains [`CilObjectData`], the primary internal data holder for all parsed
//! metadata from a .NET assembly. It serves as the foundation for the metadata loading
//! pipeline and coordinates the parallel parsing of metadata tables, streams, and
//! cross-references.
//!
//! # Architecture Overview
//!
//! The [`CilObjectData`] structure follows a two-phase loading approach:
//! 1. **Stream Parsing**: Load metadata streams (#Strings, #Blob, #GUID, etc.)
//! 2. **Parallel Loading**: Execute specialized loaders for different table categories
//!
//! # Internal Use Only
//!
//! This module is designed for internal use by the loader system and should not be
//! exposed to external users. The public API is provided through [`crate::CilObject`]
//! which wraps and manages the underlying [`CilObjectData`].
//!
//! # Loading Pipeline
//!
//! ```text
//! File Input → Stream Parsing → Context Creation → Parallel Loaders → Final Object
//!     ↓              ↓               ↓                    ↓              ↓
//!   Raw PE      #Strings,etc.   LoaderContext      Table Population   CilObject
//!  Assembly       Streams        Creation          & Cross-refs      Ready for Use
//! ```
//!
//! # Key Components
//!
//! - **Metadata Streams**: String heap, blob heap, GUID heap, user strings
//! - **Table Maps**: Concurrent containers for all metadata table types
//! - **Type System**: Central registry for type definitions and references
//! - **Import/Export**: Dependency tracking and external reference management
//! - **Resources**: Embedded resource management and access
//!
//! # Memory Management
//!
//! The structure uses careful memory management:
//! - **Reference Counting**: Shared ownership of complex objects
//! - **Lazy Loading**: Some components use `OnceLock` for deferred initialization
//! - **Concurrent Access**: Thread-safe data structures for parallel loading
//!
//! # Error Handling
//!
//! Loading operations can fail due to:
//! - **Malformed Metadata**: Invalid stream layouts or table structures
//! - **Version Incompatibility**: Unsupported metadata format versions
//! - **Resource Constraints**: Memory allocation failures
//! - **File Corruption**: Inconsistent or damaged assembly files
//!
//! # Thread Safety
//!
//! All components in this module are designed for safe concurrent access during parallel loading.
//! The internal data structures are [`std::marker::Send`] and [`std::marker::Sync`],
//! enabling parallel metadata processing across multiple threads with lock-free data structures.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::loader::context`] - Loading context creation and parallel coordination
//! - [`crate::metadata::streams`] - Metadata stream parsing and validation
//! - [`crate::metadata::typesystem`] - Type registry initialization and management
//! - [`crate::metadata::tables`] - Metadata table loading and cross-reference resolution

use std::sync::{Arc, OnceLock};

use crossbeam_skiplist::SkipMap;

use crate::{
    metadata::{
        cilassemblyview::CilAssemblyView,
        diagnostics::DiagnosticCategory,
        exports::{NativeExports, UnifiedExportContainer},
        imports::{NativeImports, UnifiedImportContainer},
        loader::{execute_loaders_in_parallel, LoaderContext, PdbSource},
        method::MethodMap,
        pdb::{
            codeview_pdb_id, embedded_portable_pdb, PdbMetadata, PdbOrigin, PortablePdb, PDB_TABLES,
        },
        resources::Resources,
        tables::{
            AssemblyOsRc, AssemblyProcessorRc, AssemblyRc, AssemblyRefMap, CustomAttributeMap,
            DeclSecurityMap, FieldMap, FileMap, MemberRefMap, MethodSpecMap, ModuleRc,
            ModuleRefMap,
        },
        typesystem::TypeRegistry,
    },
    project::ProjectContext,
    Result,
};

/// Core data structure holding all parsed metadata for a .NET assembly.
///
/// This structure serves as the central repository for all metadata extracted from a
/// .NET assembly file. It coordinates the parsing of PE headers, metadata streams,
/// and table structures while providing the foundation for parallel metadata loading
/// operations.
///
/// # Structure Organization
///
/// **File Context**: Original file reference and raw binary data
/// **Headers**: CLR header and metadata root information\
/// **Streams**: Parsed metadata streams (strings, blobs, GUIDs, etc.)
/// **Tables**: Concurrent maps for all metadata table types
/// **Registries**: Type system, imports, exports, and resource management
///
/// # Loading Process
///
/// 1. **Initialization**: Parse PE headers and locate metadata
/// 2. **Stream Loading**: Extract and parse metadata streams via `load_streams`
/// 3. **Context Creation**: Build internal loader context for parallel loading
/// 4. **Parallel Execution**: Run specialized loaders for different table categories
/// 5. **Finalization**: Complete cross-references and semantic relationships
///
/// # Memory Layout
///
/// The structure maintains careful separation between:
/// - **Owned Data**: Parsed structures and computed relationships
/// - **Shared Data**: Reference-counted objects for concurrent access
/// - **Lazy Data**: Deferred initialization for optional components
///
/// # Thread Safety
///
/// [`CilObjectData`] is [`std::marker::Send`] and [`std::marker::Sync`], designed for safe concurrent access:
/// - Metadata streams are immutable after parsing
/// - Table maps use concurrent data structures ([`crossbeam_skiplist::SkipMap`])
/// - Reference counting enables safe sharing via [`std::sync::Arc`]
/// - Atomic operations coordinate loader synchronization using [`std::sync::OnceLock`]
/// - Lock-free access patterns minimize contention during parallel loading
///
/// # Internal Use
///
/// This structure is internal to the loader system. External code should use
/// [`crate::CilObject`] which provides a safe, ergonomic interface to the
/// underlying metadata.
pub(crate) struct CilObjectData {
    /// Assembly references to external .NET assemblies.
    pub refs_assembly: AssemblyRefMap,
    /// Module references to external modules and native libraries.
    pub refs_module: ModuleRefMap,
    /// Member references to external methods and fields.
    pub refs_member: MemberRefMap,
    /// File references for multi-file assemblies.
    pub refs_file: FileMap,
    /// Security declarations for permissions and security attributes.
    pub decl_security: DeclSecurityMap,

    /// Primary module definition for this assembly.
    pub module: OnceLock<ModuleRc>,
    /// Assembly definition containing version and identity information.
    pub assembly: OnceLock<AssemblyRc>,
    /// Operating system requirements for the assembly.
    pub assembly_os: OnceLock<AssemblyOsRc>,
    /// Processor architecture requirements for the assembly.
    pub assembly_processor: OnceLock<AssemblyProcessorRc>,

    /// Central type registry managing all type definitions and references.
    pub types: Arc<TypeRegistry>,
    /// Unified import container for both CIL and native imports.
    pub import_container: UnifiedImportContainer,
    /// Unified export container for both CIL and native exports.
    pub export_container: UnifiedExportContainer,
    /// Method definitions and implementation details.
    pub methods: MethodMap,
    /// Generic method instantiation specifications.
    pub method_specs: MethodSpecMap,
    /// Field definitions, by token.
    pub fields: FieldMap,
    /// Custom attributes, by their CustomAttribute row's token.
    pub custom_attributes: CustomAttributeMap,
    /// Embedded resource management and access.
    pub resources: Resources,
    /// The assembly's Portable PDB: an attached standalone one, else the one the image
    /// embeds, else the debug tables in the image's own metadata; `None` without any.
    pub pdb: Option<PortablePdb>,
}

impl CilObjectData {
    /// Parse and load .NET assembly metadata from a CilAssemblyView.
    ///
    /// This is the main entry point for loading metadata from a .NET assembly.
    /// It adapts the existing complex multi-threaded loader to work with CilAssemblyView
    /// instead of direct file access, preserving all the sophisticated parallel loading
    /// architecture while eliminating lifetime dependencies.
    ///
    /// # Loading Pipeline
    ///
    /// 1. **Initialize Concurrent Containers**: Create all SkipMap containers for parallel loading
    /// 2. **Native Table Loading**: Load PE import/export tables via CilAssemblyView
    /// 3. **Registry Coordination**: Register with ProjectContext for multi-assembly synchronization (if provided)
    /// 4. **Context Creation**: Build internal loader context using CilAssemblyView
    /// 5. **Parallel Loading**: Execute the complex parallel loaders with barrier synchronization
    /// 6. **Cross-Reference Resolution**: Build semantic relationships between tables
    ///
    /// # Arguments
    /// * `view` - Reference to the CilAssemblyView containing parsed raw metadata
    /// * `project_context` - Optional ProjectContext for coordinating multi-assembly parallel loading
    ///   with barrier synchronization to handle circular dependencies.
    /// * `lenient` - Whether a malformed row is a diagnostic rather than an error
    /// * `standalone_pdb` - A standalone Portable PDB to read the debug information from,
    ///   instead of the one the image embeds or its own debug tables
    ///
    /// # Returns
    /// A fully loaded [`CilObjectData`] instance ready for metadata queries and analysis.
    ///
    /// # Errors
    /// Returns [`crate::Error`] if:
    /// - **Metadata Format**: Malformed metadata streams or tables
    /// - **Version Support**: Unsupported metadata format version
    /// - **Memory**: Insufficient memory for loading large assemblies
    /// - **Corruption**: Inconsistent or damaged metadata structures
    /// - **Standalone PDB**: In strict mode, a `standalone_pdb` that does not read, or was
    ///   written for an image with other row counts. The image's own PDB never fails the
    ///   load: the runtime never reads it, so a malformed one is a diagnostic.
    ///
    /// # Examples
    ///
    /// The `examples::from_assembly_view_example` test in this module runs this example.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe but should only be called once per CilAssemblyView.
    /// The resulting [`CilObjectData`] can be safely accessed from multiple threads.
    pub(crate) fn from_assembly_view(
        view: &CilAssemblyView,
        project_context: Option<&ProjectContext>,
        lenient: bool,
        standalone_pdb: Option<&[u8]>,
    ) -> Result<Self> {
        // Get real assembly identity (None for netmodules)
        let real_identity = view.identity()?;

        // For TypeRegistry, we always need an identity - use fallback for netmodules
        let type_registry_identity = view.identity_or_fallback()?;

        let mut cil_object = CilObjectData {
            refs_assembly: SkipMap::default(),
            refs_module: SkipMap::default(),
            refs_member: SkipMap::default(),
            refs_file: SkipMap::default(),
            decl_security: SkipMap::default(),
            module: OnceLock::new(),
            assembly: OnceLock::new(),
            assembly_os: OnceLock::new(),
            assembly_processor: OnceLock::new(),
            types: Arc::new(TypeRegistry::new(type_registry_identity)?),
            import_container: UnifiedImportContainer::new(),
            export_container: UnifiedExportContainer::new(),
            methods: SkipMap::default(),
            method_specs: SkipMap::default(),
            fields: SkipMap::default(),
            custom_attributes: SkipMap::default(),
            resources: Resources::new(view.file().clone()),
            pdb: None,
        };

        // The PDB: an attached standalone one, else the one the image embeds, else debug
        // tables in the image's own metadata. The image's own PDB is read leniently whatever
        // the load's mode, since the runtime never reads it to load the assembly; a broken
        // embedded PDB leaves the image's own tables, if it has any.
        let diagnostics = view.diagnostics();
        let embedded = if standalone_pdb.is_some() {
            None
        } else {
            embedded_portable_pdb(view.file()).unwrap_or_else(|e| {
                diagnostics.warning(
                    DiagnosticCategory::General,
                    format!("Skipped the embedded Portable PDB: {e}"),
                );
                None
            })
        };
        let mut pdb_metadata = None;
        let attached = standalone_pdb
            .map(|data| (data, PdbOrigin::Standalone, lenient))
            .or_else(|| {
                embedded
                    .as_deref()
                    .map(|data| (data, PdbOrigin::Embedded, true))
            });
        if let Some((data, origin, pdb_lenient)) = attached {
            match PdbMetadata::read(data).and_then(|pdb| {
                pdb.check_rows(view.tables())?;
                Ok(pdb)
            }) {
                Ok(pdb) => {
                    match codeview_pdb_id(view.file()) {
                        Ok(Some(id)) if id != pdb.pdb_stream.id => diagnostics.warning(
                            DiagnosticCategory::General,
                            format!(
                                "The {origin} Portable PDB's id is not the one the image's \
                                 CodeView entry names: it is from another build"
                            ),
                        ),
                        Err(e) => diagnostics.warning(
                            DiagnosticCategory::General,
                            format!("Could not read the CodeView entry's PDB id: {e}"),
                        ),
                        _ => {}
                    }
                    pdb_metadata = Some((pdb, origin, pdb_lenient));
                }
                Err(e) if pdb_lenient => diagnostics.warning(
                    DiagnosticCategory::General,
                    format!("Skipped the {origin} Portable PDB: {e}"),
                ),
                Err(e) => return Err(e),
            }
        }
        cil_object.pdb = match &pdb_metadata {
            Some((pdb, origin, _)) => Some(PortablePdb::new(*origin, Some(pdb.pdb_stream.clone()))),
            None if view.tables().is_some_and(|tables| {
                PDB_TABLES
                    .iter()
                    .any(|&table| tables.table_row_count(table) > 0)
            }) =>
            {
                Some(PortablePdb::new(PdbOrigin::InImage, None))
            }
            None => None,
        };

        let (native_imports, native_exports) = load_native_tables(view)?;
        *cil_object.import_container.native_mut() = native_imports;
        *cil_object.export_container.native_mut() = native_exports;

        // Only register with project context if we have a real assembly identity.
        // Netmodules (which return None for identity) should not be registered
        // as separate assemblies in the project context - they're part of another assembly.
        if let (Some(context), Some(identity)) = (project_context, real_identity) {
            context.register_and_wait_stage1(identity, cil_object.types.clone())?;
            context.link_all_registries(&cil_object.types);
        }

        {
            let context = LoaderContext {
                input: view.file().clone(),
                data: view.data(),
                header: view.cor20header(),
                header_root: view.metadata_root(),
                diagnostics: view.diagnostics(),
                lenient,
                meta: view.tables(),
                strings: view.strings(),
                userstrings: view.userstrings(),
                guids: view.guids(),
                blobs: view.blobs(),
                assembly: &cil_object.assembly,
                assembly_os: &cil_object.assembly_os,
                assembly_processor: &cil_object.assembly_processor,
                assembly_ref: &cil_object.refs_assembly,
                assembly_ref_os: SkipMap::default(),
                assembly_ref_processor: SkipMap::default(),
                module: &cil_object.module,
                module_ref: &cil_object.refs_module,
                type_spec: SkipMap::default(),
                method_def: &cil_object.methods,
                method_impl: SkipMap::default(),
                method_semantics: SkipMap::default(),
                method_spec: &cil_object.method_specs,
                field: &cil_object.fields,
                field_ptr: SkipMap::default(),
                method_ptr: SkipMap::default(),
                field_layout: SkipMap::default(),
                field_marshal: SkipMap::default(),
                field_rva: SkipMap::default(),
                enc_log: SkipMap::default(),
                enc_map: SkipMap::default(),
                pdb: cil_object.pdb.as_ref().map(|target| match &pdb_metadata {
                    Some((pdb, _, pdb_lenient)) => PdbSource {
                        meta: pdb.tables.as_ref(),
                        strings: pdb.strings.as_ref(),
                        blobs: pdb.blobs.as_ref(),
                        guids: pdb.guids.as_ref(),
                        lenient: *pdb_lenient,
                        target,
                    },
                    None => PdbSource {
                        meta: view.tables(),
                        strings: view.strings(),
                        blobs: view.blobs(),
                        guids: view.guids(),
                        lenient: true,
                        target,
                    },
                }),
                param: SkipMap::default(),
                param_ptr: SkipMap::default(),
                generic_param: SkipMap::default(),
                generic_param_constraint: SkipMap::default(),
                property: SkipMap::default(),
                property_ptr: SkipMap::default(),
                property_map: SkipMap::default(),
                event: SkipMap::default(),
                event_ptr: SkipMap::default(),
                event_map: SkipMap::default(),
                member_ref: &cil_object.refs_member,
                class_layout: SkipMap::default(),
                nested_class: SkipMap::default(),
                interface_impl: SkipMap::default(),
                constant: SkipMap::default(),
                custom_attribute: &cil_object.custom_attributes,
                decl_security: &cil_object.decl_security,
                file: &cil_object.refs_file,
                exported_type: cil_object.export_container.cil(),
                standalone_sig: SkipMap::default(),
                imports: cil_object.import_container.cil(),
                resources: &cil_object.resources,
                types: &cil_object.types,
            };

            execute_loaders_in_parallel(&context, project_context)?;

            // Wait for all assemblies to complete all loaders before returning.
            // This ensures nested type relationships and other cross-assembly dependencies
            // are fully populated before validation can access them.
            if let Some(proj_ctx) = project_context {
                proj_ctx.wait_stage4()?;
            }
        }

        Ok(cil_object)
    }
}

/// Loads native PE import and export tables from a CilAssemblyView.
///
/// This standalone function extracts native imports and exports from the PE file
/// structure, returning them as a tuple for integration into the import/export containers.
///
/// # Arguments
///
/// * `view` - Reference to the CilAssemblyView containing the PE file data.
///
/// # Returns
///
/// A tuple of `(NativeImports, NativeExports)` containing the parsed native tables.
/// Returns default (empty) containers if the PE file has no imports or exports.
///
/// # Errors
///
/// Returns an error if import or export table parsing fails due to malformed data.
fn load_native_tables(view: &CilAssemblyView) -> Result<(NativeImports, NativeExports)> {
    let native_imports = if let Some(owned_imports) = view.file().imports() {
        if owned_imports.is_empty() {
            NativeImports::default()
        } else {
            let is_pe32_plus = view.file().is_pe32_plus_format().unwrap_or(false);
            NativeImports::from_pe_imports(owned_imports, is_pe32_plus)?
        }
    } else {
        NativeImports::default()
    };

    // The runtime does not read a managed assembly's native exports, so a table the model
    // cannot hold (a name exported twice) does not fail the load: the view is empty, the
    // entries stay on `File::pe().exports`, and the writer refuses to rebuild the table
    let pe = view.file().pe();
    let native_exports = match &pe.export_header {
        Some(header) => NativeExports::from_pe_exports(header, &pe.exports)
            .unwrap_or_else(|_| NativeExports::new(&header.name)),
        None => NativeExports::default(),
    };

    Ok((native_imports, native_exports))
}

#[cfg(test)]
mod examples {
    use super::*;
    use crate::{metadata::tables::TableId, testkit::fixture, Result};

    /// Loading runs every table loader; the types and methods of the file are then there.
    #[test]
    fn from_assembly_view_example() -> Result<()> {
        // Create CilAssemblyView first
        let view = CilAssemblyView::from_path(fixture("crafted_2.exe"))?;

        // Load single assembly without ProjectContext
        let cil_data = CilObjectData::from_assembly_view(&view, None, false, None)?;

        // Metadata is now ready for use
        assert!(cil_data.types.len() > 1);
        let method_rows = view
            .tables()
            .expect("tables")
            .table_row_count(TableId::MethodDef);
        assert_eq!(
            cil_data.methods.len(),
            usize::try_from(method_rows).unwrap()
        );
        Ok(())
    }
}

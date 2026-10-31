//! PE file generator for the assembly writer.
//!
//! This module provides the [`PeGenerator`] that orchestrates complete PE file generation
//! from a [`CilAssembly`]. The generator uses a streaming approach where content is written
//! sequentially and forward-referenced values are patched via fixups at the end.
//!
//! # Generation Process
//!
//! The generator follows this sequence:
//!
//! 1. **Initialize**: Create WriteContext with estimated file size
//! 2. **Write**: Stream all content sequentially:
//!    - PE Headers (DOS, PE signature, COFF, Optional, Section Table)
//!    - .text Section (IAT, COR20 header, method bodies, metadata)
//!    - Import/Export Data
//!    - Additional Sections (.rsrc, .reloc)
//! 3. **Fixup**: Patch headers with final values (sizes, RVAs, checksum)
//! 4. **Truncate**: Remove over-allocated space
//!
//! # Architecture
//!
//! The key insight is that we don't need to pre-calculate everything. Instead:
//!
//! - **Streaming writes**: Write content as we go, tracking positions
//! - **Fixups**: Headers that need forward-referenced values get patched at the end
//! - **Context carries state**: WriteContext holds all positions and values we need
//!
//! # References
//!
//! - ECMA-335 §II.25 - File format extensions to PE
//! - [PE Format Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io::Write,
    path::Path,
    sync::Arc,
};

use log::debug;
use strum::IntoEnumIterator;

#[cfg(feature = "x86")]
use crate::analysis::x86_native_body_size;
use crate::{
    assembly::{decode_stream, Operand},
    cilassembly::{
        changes::{AssemblyChanges, ChangeRef, METHOD_BODY_PLACEHOLDER_BASE},
        cleanup::collect_referenced_heap_entries,
        writer::{
            blobs::{debug_blobs, signature_blobs, BlobRemap},
            context::{SectionWriteInfo, WriteContext, FILE_ALIGNMENT_DEFAULT},
            fields::{resolve_field_data_rva, write_field_data},
            fixups::{apply_all_fixups, fixup_metadata_stream_headers},
            heaps::{
                patch_row_heap_refs, precompute_heap_offsets, stream_blob_heap, stream_guid_heap,
                stream_strings_heap, stream_userstring_heap,
            },
            methods::rebuild_method_body,
            output::Output,
            relocations::{generate_relocations, RelocationConfig},
            remapper::{RemapReferences, RidRemapper},
        },
        CilAssembly, Operation, TableModifications,
    },
    dispatch_table_type,
    file::{
        pe::{
            relocate_resource_section, DataDirectoryType, DosHeader, Import, PeCharacteristics,
            SectionTable,
        },
        File,
    },
    metadata::{
        cor20header::Cor20Flags,
        exports::NativeExports,
        imports::NativeImports,
        method::{MethodBody, MethodImplCodeType},
        root::Root,
        streams::{Blob, Guid, StreamHeader, Strings, UserStrings},
        tablefields::get_heap_fields,
        tables::{
            skip_unreadable, ManifestResourceRaw, MethodDefRaw, RowWritable, StandAloneSigRaw,
            TableDataOwned, TableId, TableInfoRef,
        },
        token::Token,
    },
    utils::{align_to, calculate_table_row_size},
    Error, Parser, Result,
};

/// Upper bound on how far the native-stub decoder will scan for a function end.
///
/// The scan window is otherwise "this PE section", which for a small file can still be the
/// bulk of it. A native stub in a mixed-mode assembly is kilobytes of code; anything past this
/// is not a stub whose extent we failed to find, it is a region we should refuse to guess at.
#[cfg(feature = "x86")]
const MAX_NATIVE_BODY_SCAN_BYTES: usize = 64 * 1024;

/// IAT (Import Address Table) size for .NET executables (8 bytes).
const IAT_SIZE: u64 = 8;

/// Configuration options for PE file generation.
///
/// Controls assembly writing behavior:
/// - **Section exclusion**: Removes specified PE sections from output
/// - **Method body handling**: Controls whether original bodies are preserved
///
/// Note: Heap deduplication and table compaction are always enabled for
/// optimal output. Tables are always rebuilt fresh to ensure consistency.
#[derive(Debug, Clone, Default)]
pub struct GeneratorConfig {
    /// PE sections to exclude from the output.
    ///
    /// Section names in this set will be skipped during PE generation.
    /// This is useful for removing artifact sections from deobfuscated assemblies,
    /// such as encrypted data sections created by obfuscators.
    ///
    /// Note: Standard sections like .text, .rsrc, and .reloc have special handling
    /// and cannot be excluded via this mechanism.
    ///
    /// Default: empty (no sections excluded)
    pub excluded_sections: HashSet<String>,

    /// Skip copying original method bodies from source assembly.
    ///
    /// When enabled, the generator will not copy the original method body region
    /// from the source PE file. This is useful for deobfuscation where all method
    /// bodies have been regenerated and the original (potentially encrypted)
    /// bodies should be discarded.
    ///
    /// When disabled (default), original method bodies are preserved and new
    /// bodies are appended after them.
    ///
    /// Default: `false`
    pub skip_original_method_bodies: bool,

    /// What the write does with a reference to a row it deletes.
    ///
    /// Default: [`DanglingPolicy::Error`]
    pub dangling: DanglingPolicy,
}

/// What a write does with a reference to a row it deletes.
///
/// Deleting a row shifts the rows after it, so a reference to the deleted row has nowhere
/// to go: the writer never retargets it to a neighbour.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DanglingPolicy {
    /// Fail the write with [`Error::DanglingReference`](crate::Error::DanglingReference).
    #[default]
    Error,
    /// Write a null reference in its place, and log a warning naming both rows.
    Null,
}

impl GeneratorConfig {
    /// Creates a new configuration with default settings.
    ///
    /// # Returns
    ///
    /// A new `GeneratorConfig` with:
    /// - `excluded_sections`: empty
    /// - `skip_original_method_bodies`: `false`
    /// - `dangling`: [`DanglingPolicy::Error`]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the PE sections to exclude from the output.
    ///
    /// Section names in this set will be skipped during PE generation.
    /// This is useful for removing artifact sections from deobfuscated assemblies.
    ///
    /// # Arguments
    ///
    /// * `sections` - Set of section names to exclude
    ///
    /// # Returns
    ///
    /// The modified configuration for method chaining.
    #[must_use]
    pub fn with_excluded_sections(mut self, sections: HashSet<String>) -> Self {
        self.excluded_sections = sections;
        self
    }

    /// Enables or disables skipping original method bodies.
    ///
    /// When enabled, the generator will not copy the original method body region
    /// from the source PE file. This is essential for deobfuscation where all
    /// method bodies have been regenerated and the original (encrypted/obfuscated)
    /// bodies should be discarded.
    ///
    /// # Arguments
    ///
    /// * `enabled` - Whether to skip copying original method bodies
    ///
    /// # Returns
    ///
    /// The modified configuration for method chaining.
    #[must_use]
    pub fn with_skip_original_method_bodies(mut self, enabled: bool) -> Self {
        self.skip_original_method_bodies = enabled;
        self
    }

    /// Sets what the write does with a reference to a row it deletes.
    ///
    /// # Arguments
    ///
    /// * `policy` - Fail the write, or write a null reference
    ///
    /// # Returns
    ///
    /// The modified configuration for method chaining.
    #[must_use]
    pub fn with_dangling(mut self, policy: DanglingPolicy) -> Self {
        self.dangling = policy;
        self
    }
}

/// The tables ECMA-335 §II.22 and the Portable PDB format require sorted, in
/// the order the writer settles them.
///
/// A table comes after every sorted table its key refers to: a
/// GenericParamConstraint is keyed by its GenericParam, and a CustomAttribute
/// or CustomDebugInformation by a parent that can be a row of most of the
/// others. Its key is then computed with those references already remapped to
/// where their rows land.
const SORTED_TABLES: &[TableId] = &[
    TableId::GenericParam,
    TableId::GenericParamConstraint,
    TableId::InterfaceImpl,
    TableId::DeclSecurity,
    TableId::MethodImpl,
    TableId::MethodSemantics,
    TableId::NestedClass,
    TableId::ClassLayout,
    TableId::FieldLayout,
    TableId::FieldRVA,
    TableId::FieldMarshal,
    TableId::Constant,
    TableId::ImplMap,
    TableId::LocalScope,
    TableId::StateMachineMethod,
    TableId::CustomAttribute,
    TableId::CustomDebugInformation,
];

/// A row of any table, as the writer serializes it.
///
/// [`RowWritable`] is implemented per row type and is not object safe; this
/// lets one routine produce the rows of every table.
trait RowSource {
    /// The row's [sort key](RowWritable::sort_key).
    fn key(&self, sizes: &TableInfoRef) -> Result<Option<(u32, u32)>>;

    /// Serializes the row, as [`RowWritable::row_write`].
    fn write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<()>;
}

impl<R: RowWritable> RowSource for R {
    fn key(&self, sizes: &TableInfoRef) -> Result<Option<(u32, u32)>> {
        self.sort_key(sizes)
    }

    fn write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<()> {
        self.row_write(data, offset, rid, sizes)
    }
}

/// Receives each row written: its RID, its sort key when its table is sorted,
/// and its bytes.
type RowSink<'a> = dyn FnMut(u32, Option<(u32, u32)>, &[u8]) -> Result<()> + 'a;

/// What rows need from the write context once the method bodies, field data
/// and resources are laid out: where RVAs and offsets moved, and which
/// duplicate signatures are dropped.
struct RowFixups {
    method_body_rva_map: HashMap<u32, u32>,
    field_data_rva_map: HashMap<u32, u32>,
    resource_offset_remap: HashMap<u32, u32>,
    original_rva_delta: i32,
    standalonesig_skip: HashSet<u32>,
}

impl RowFixups {
    fn from_context(ctx: &WriteContext) -> Self {
        Self {
            method_body_rva_map: ctx.method_body_rva_map.clone(),
            field_data_rva_map: ctx.field_data_rva_map.clone(),
            resource_offset_remap: ctx.resource_offset_remap.clone(),
            original_rva_delta: ctx.original_method_rva_delta,
            standalonesig_skip: ctx.standalonesig_skip.clone(),
        }
    }

    /// Applies the RVA and offset fixups to a serialized row of `table_id`.
    fn apply(&self, buffer: &mut [u8], table_id: TableId) {
        PeGenerator::apply_rva_fixups(
            buffer,
            table_id,
            &self.method_body_rva_map,
            &self.field_data_rva_map,
            &self.resource_offset_remap,
            self.original_rva_delta,
        );
    }
}

/// PE file generator that orchestrates complete file generation.
///
/// The `PeGenerator` takes a `CilAssembly` and generates a complete, valid PE file
/// using a streaming write approach with fixups applied at the end.
///
/// # Configuration
///
/// The generator supports configuration options via [`GeneratorConfig`]:
///
/// ```no_run
/// let generator = PeGenerator::new(&assembly)
///     .with_config(GeneratorConfig::default());
/// ```
///
/// Or using the builder pattern:
///
/// ```no_run
/// let generator = PeGenerator::with_config(
///     &assembly,
///     GeneratorConfig::new()
///         .with_skip_original_method_bodies(true)
/// );
/// ```
pub struct PeGenerator<'a> {
    assembly: &'a CilAssembly,
    config: GeneratorConfig,
}

impl<'a> PeGenerator<'a> {
    /// Creates a new PE generator for the given assembly with default configuration.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to generate a PE file from
    ///
    /// # Returns
    ///
    /// A new `PeGenerator` with default configuration:
    /// - Heap deduplication: enabled
    /// - Dead reference elimination: disabled
    pub fn new(assembly: &'a CilAssembly) -> Self {
        Self {
            assembly,
            config: GeneratorConfig::default(),
        }
    }

    /// Creates a new PE generator with the specified configuration.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to generate a PE file from
    /// * `config` - Configuration options controlling generation behavior
    ///
    /// # Returns
    ///
    /// A new `PeGenerator` with the specified configuration.
    pub fn with_config(assembly: &'a CilAssembly, config: GeneratorConfig) -> Self {
        Self { assembly, config }
    }

    /// Returns the current generator configuration.
    ///
    /// # Returns
    ///
    /// A reference to the current [`GeneratorConfig`].
    pub fn config(&self) -> &GeneratorConfig {
        &self.config
    }

    /// Sets the generator configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The new configuration to use for generation
    pub fn set_config(&mut self, config: GeneratorConfig) {
        self.config = config;
    }

    /// Generates a complete PE file to the specified path.
    ///
    /// This is the main entry point for PE file generation. It performs the complete
    /// generation process including:
    ///
    /// 1. Writing PE headers (DOS, COFF, Optional, Section Table)
    /// 2. Writing the .text section (IAT, COR20 header, method bodies, metadata)
    /// 3. Copying preserved sections (.rsrc, .reloc)
    /// 4. Applying fixups to headers with final values
    /// 5. Calculating and writing the PE checksum
    ///
    /// # Arguments
    ///
    /// * `path` - The file path where the PE file will be written
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful generation.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output file cannot be created or written
    /// - Memory mapping operations fail
    /// - The assembly contains invalid metadata
    /// - Layout calculation fails due to size constraints
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        debug!("Writing assembly to {}", path.as_ref().display());
        // Estimate file size for initial allocation (we'll truncate at the end)
        let estimated_size = self.estimate_file_size()?;

        // Create file-backed output
        let output = Output::create(&path, estimated_size)?;

        // Generate using internal method
        let ctx = self.generate(output)?;

        debug!("Writing assembly ({} bytes)", ctx.bytes_written);
        // Finalize file (truncate to actual size)
        ctx.output.finalize(Some(ctx.bytes_written))
    }

    /// Generates a complete PE file to memory.
    ///
    /// This method generates the PE file entirely in memory without writing to disk,
    /// returning the raw bytes. This is useful for:
    ///
    /// - In-memory assembly manipulation pipelines
    /// - Testing and validation without file I/O
    /// - Streaming assembly modifications to network or other outputs
    ///
    /// # Returns
    ///
    /// Returns `Ok(Vec<u8>)` containing the complete PE file bytes on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Memory allocation fails
    /// - The assembly contains invalid metadata
    /// - Layout calculation fails due to size constraints
    ///
    /// # Example
    ///
    /// The `examples::to_memory_example` test in this module runs this example.
    pub fn to_memory(&self) -> Result<Vec<u8>> {
        // Estimate file size for initial allocation
        let estimated_size = self.estimate_file_size()?;

        // Create in-memory output
        let output = Output::create_in_memory(estimated_size)?;

        // Generate using internal method
        let ctx = self.generate(output)?;

        debug!("Writing assembly ({} bytes)", ctx.bytes_written);
        // Extract the bytes
        ctx.output.into_vec(Some(ctx.bytes_written))
    }

    /// Internal generation method that performs the actual PE writing.
    ///
    /// This is the core generation logic shared by both `generate_to_file` and
    /// `generate_to_memory`. It takes an already-created `Output` and performs
    /// all the generation steps.
    ///
    /// # Arguments
    ///
    /// * `output` - The output target (file-backed or in-memory)
    ///
    /// # Returns
    ///
    /// Returns the `WriteContext` after generation, allowing the caller to
    /// finalize the output appropriately.
    fn generate(&self, output: Output) -> Result<WriteContext<'_>> {
        let changes = self.assembly.changes();

        // Create write context
        let mut ctx = WriteContext::new(self.assembly, changes, output)?;

        // Phase 1: Write PE headers (positions tracked in ctx)
        self.write_dos_header(&mut ctx)?;
        self.write_pe_signature(&mut ctx)?;
        self.write_coff_header(&mut ctx)?;
        self.write_optional_header(&mut ctx)?;
        self.write_section_table(&mut ctx)?;

        // Align to file alignment for .text section
        ctx.align_to_file()?;
        ctx.text_section_offset = ctx.pos();

        // Phase 2: Write .text section content
        // Only write IAT for assemblies that need native imports (e.g., mscoree.dll).
        // .NET Core PE32+ assemblies typically have no IAT, no import table, and no
        // native entry point. Adding these unconditionally triggers CoreCLR's
        // CheckILOnly validation which requires matching base relocations, causing
        // BadImageFormatException for assemblies that originally lacked them.
        if self.needs_native_imports() {
            self.write_iat(&mut ctx)?;
        }
        self.write_cor20_header(&mut ctx)?;

        // Resolve table ChangeRefs early - needed for method bodies that reference
        // newly added StandAloneSig entries (local variable signatures)
        Self::resolve_table_change_refs(changes);

        // Build RID remapper BEFORE the heap pre-pass.
        //
        // The pre-pass must see the same remap maps the real write pass will use, or the two
        // disagree on every offset after the first remapped signature blob — and the tables are
        // serialised from the pre-pass values. Building the remapper afterwards left the
        // pre-pass with empty maps by construction.
        //
        // The remapper depends only on `changes` and the original table row counts, not on any
        // heap offset, so it is safe to compute this early.
        // When TypeDef/MethodDef/etc rows are removed, subsequent rows shift down
        // and IL tokens must be updated accordingly.
        if let Some(tables) = self.assembly.view().tables() {
            let mut original_counts: HashMap<TableId, u32> = HashMap::new();
            for table_id in TableId::iter() {
                let count = tables.table_row_count(table_id);
                if count > 0 {
                    original_counts.insert(table_id, count);
                }
            }

            let remapper =
                RidRemapper::from_changes(changes, &original_counts, self.config.dangling);
            if !remapper.is_empty() {
                ctx.tokens = remapper.token_remap();
                // The blobs signature columns reference, whose type tokens follow the rows
                // the remap renumbers.
                ctx.typed_blobs = signature_blobs(self.assembly);
            }
            // The Portable PDB blobs whose content names rows or blobs: the blobs they name
            // move whenever the heap is rebuilt, with or without row renumbering, and the
            // rows a change adds are named by placeholder
            ctx.typed_blobs.extend(debug_blobs(self.assembly));

            // Build StandAloneSig deduplication mapping
            self.build_standalonesig_dedup(&mut ctx, changes);
        }

        // Every heap offset the tables and the bodies name, so that a heap rebuilt by
        // deduplication or edits keeps the ones inside another entry's bytes as well as the
        // entries
        let (strings, blobs, _) = collect_referenced_heap_entries(self.assembly);
        ctx.referenced_string_offsets = strings;
        ctx.referenced_blob_offsets = blobs;
        ctx.referenced_userstring_offsets = collect_referenced_userstring_offsets(self.assembly);

        // Pre-compute heap offsets - needed for method bodies that reference newly added
        // userstrings (ldstr instructions) and other heap entries. This resolves ChangeRefs to
        // their final heap offsets, using the remap maps established above.
        precompute_heap_offsets(self.assembly.view(), &mut ctx, changes)?;

        // Write method bodies
        ctx.align_to_4();
        ctx.method_bodies_offset = ctx.pos();
        self.write_method_bodies(&mut ctx, changes)?;
        ctx.method_bodies_size = ctx
            .pos()
            .checked_sub(ctx.method_bodies_offset)
            .ok_or_else(|| Error::LayoutFailed("Method bodies size underflow".to_string()))?;

        // Write field initialization data (FieldRVA entries)
        write_field_data(&mut ctx)?;

        // Write CLR resources section (pointed to by COR20.resource_rva/resource_size)
        ctx.align_to_4();
        self.write_resource_data(&mut ctx, changes)?;

        // Write metadata (heaps first, then tables)
        ctx.align_to_4();
        ctx.metadata_offset = ctx.pos();
        self.write_metadata(&mut ctx, changes)?;
        ctx.metadata_size = ctx
            .pos()
            .checked_sub(ctx.metadata_offset)
            .ok_or_else(|| Error::LayoutFailed("Metadata size underflow".to_string()))?;

        // Write import/export data (if present)
        if self.needs_native_imports() {
            Self::write_import_data(&mut ctx)?;
        }
        self.write_export_data(&mut ctx)?;

        // Write embedded PE resources if the original assembly had Win32 resources
        // in .text (no .rsrc section). These must be carried over to the new .text.
        self.write_embedded_pe_resources(&mut ctx)?;

        // Keep the debug directory when the write changes nothing: its data still
        // describes the code
        if !changes.has_changes() {
            self.write_debug_data(&mut ctx)?;
        }

        // Calculate .text section size and update sections vector
        ctx.text_section_size = ctx
            .pos()
            .checked_sub(ctx.text_section_offset)
            .ok_or_else(|| Error::LayoutFailed(".text section size underflow".to_string()))?;
        let text_size_u32 = u32::try_from(ctx.text_section_size).unwrap_or(u32::MAX);
        if let Some(idx) = ctx.find_section_index(".text") {
            // `.text` is regenerated, so its virtual extent and its written length are the
            // same measured `pos()` delta.
            ctx.update_section(
                idx,
                ctx.text_section_offset,
                ctx.text_section_rva,
                text_size_u32,
                text_size_u32,
            );
        }

        // Align to file alignment for next section
        ctx.align_to_file()?;

        // Phase 3: Write additional sections (in order they appear in section table)
        self.write_other_sections(&mut ctx)?;

        // Phase 4: Apply fixups (patch headers with final values)
        apply_all_fixups(&mut ctx)?;

        debug!(
            "PE layout: .text={}, methods={} bytes, metadata={} bytes",
            ctx.text_section_size, ctx.method_bodies_size, ctx.metadata_size
        );
        debug!("Applied {} RID remappings", ctx.tokens.len());

        Ok(ctx)
    }

    /// Estimates the total file size for initial allocation.
    ///
    /// The output starts at this size, grows when a write runs past it (the estimate leaves
    /// out table rows and index widening), and is truncated to the actual size at the end.
    ///
    /// # Returns
    ///
    /// The estimated file size in bytes, aligned to file alignment.
    ///
    /// # Errors
    ///
    /// Returns an error if method body size calculation fails.
    fn estimate_file_size(&self) -> Result<u64> {
        let view = self.assembly.view();
        let file = view.file();

        // Get original file size as base estimate
        let original_size = file.data().len() as u64;

        // Add room for modifications (new methods, new heap entries, field data, etc.)
        let changes = self.assembly.changes();
        let method_bodies_expansion = u64::from(changes.method_bodies_total_size()?);
        let field_data_expansion = u64::from(changes.field_data_total_size()?);

        // Estimate heap expansion
        let heap_expansion = self.estimate_heap_expansion();

        // Estimate original FieldRVA data that will be relocated
        // (this may duplicate data already in original_size, but we're being conservative)
        let fieldrva_expansion = self.estimate_fieldrva_data_size();

        // Add 20% buffer for safety
        let estimated = original_size
            .checked_add(method_bodies_expansion)
            .and_then(|v| v.checked_add(field_data_expansion))
            .and_then(|v| v.checked_add(heap_expansion))
            .and_then(|v| v.checked_add(fieldrva_expansion))
            .ok_or_else(|| Error::LayoutFailed("File size estimate overflow".to_string()))?;
        let with_buffer = estimated
            .checked_mul(120)
            .map(|v| v / 100)
            .ok_or_else(|| Error::LayoutFailed("File size estimate overflow".to_string()))?;

        // Align to file alignment
        Ok(align_to(with_buffer, u64::from(FILE_ALIGNMENT_DEFAULT)))
    }

    /// Estimates the size of original FieldRVA data that will be relocated.
    fn estimate_fieldrva_data_size(&self) -> u64 {
        let view = self.assembly.view();
        let Some(tables) = view.tables() else {
            return 0;
        };
        let Some(fieldrva_table) = tables.table::<MethodDefRaw>().map(|_| {
            // Use FieldRvaRaw if available
            tables.table_row_count(TableId::FieldRVA)
        }) else {
            return 0;
        };

        // Conservative estimate: assume average 64 bytes per FieldRVA entry
        // (typical for small arrays, struct data, etc.)
        u64::from(fieldrva_table) * 64
    }

    /// Estimates additional heap space needed for modifications.
    ///
    /// Calculates the total bytes needed for all appended heap entries including
    /// strings, blobs, GUIDs, and user strings.
    ///
    /// # Returns
    ///
    /// The estimated additional heap space in bytes.
    fn estimate_heap_expansion(&self) -> u64 {
        let changes = self.assembly.changes();
        let mut expansion = 0u64;

        // Add space for appended strings
        for (data, _) in changes.string_heap_changes.appended_iter() {
            // +1 for null terminator. Saturate on absurd estimate; final emission validates.
            expansion = expansion.saturating_add((data.len() as u64).saturating_add(1));
        }

        // Add space for appended blobs
        for (data, _) in changes.blob_heap_changes.appended_iter() {
            // +5 for max compressed length prefix
            expansion = expansion.saturating_add((data.len() as u64).saturating_add(5));
        }

        // Add space for appended GUIDs
        let guid_count = changes.guid_heap_changes.appended_iter().count() as u64;
        expansion = expansion.saturating_add(guid_count.saturating_mul(16));

        // Add space for appended user strings
        for (data, _) in changes.userstring_heap_changes.appended_iter() {
            // +5 for max compressed length prefix
            expansion = expansion.saturating_add((data.len() as u64).saturating_add(5));
        }

        expansion
    }

    /// Writes the DOS header with standard stub.
    ///
    /// Copies the original DOS header from the source assembly, preserving any
    /// custom DOS stub. The `e_lfanew` field at offset 0x3C is fixed up later.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if reading from the source or writing fails.
    fn write_dos_header(&self, ctx: &mut WriteContext) -> Result<()> {
        ctx.dos_header_offset = ctx.pos();

        let view = self.assembly.view();
        let file = view.file();

        // Copy original DOS header (preserves any custom DOS stub)
        let dos_size = DosHeader::STANDARD_SIZE;
        let original_dos = file.data_slice(0, dos_size)?;
        ctx.write(original_dos)?;

        // e_lfanew at offset 0x3C will be fixed up later

        Ok(())
    }

    /// Writes the PE signature ("PE\0\0").
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    fn write_pe_signature(&self, ctx: &mut WriteContext) -> Result<()> {
        let _ = self; // Method signature kept for consistency
        ctx.pe_signature_offset = ctx.pos();
        ctx.write(b"PE\0\0")?;
        Ok(())
    }

    /// Writes the COFF header.
    ///
    /// Clones the original COFF header and patches fields that may change:
    /// - number_of_sections (if we add/remove sections)
    /// - size_of_optional_header (format-dependent)
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    fn write_coff_header(&self, ctx: &mut WriteContext) -> Result<()> {
        ctx.coff_header_offset = ctx.pos();

        let view = self.assembly.view();
        let pe = view.file().pe();

        // Clone and modify the COFF header
        let mut coff_header = pe.coff_header.clone();
        coff_header.number_of_sections = ctx.section_count;
        coff_header.size_of_optional_header =
            u16::try_from(ctx.optional_header_size()).map_err(|_| {
                Error::LayoutFailed(format!(
                    "Optional header size {} exceeds u16 range",
                    ctx.optional_header_size()
                ))
            })?;

        // Write using the struct's write_to method
        coff_header.write_to(ctx)?;

        Ok(())
    }

    /// Writes the optional header.
    ///
    /// Clones the original optional header and zeroes invalid data directories:
    /// - CertificateTable: Signature is invalidated by any modification
    /// - Debug: Debug info becomes stale (IL offsets change, PDB correlation breaks); a write
    ///   that changes nothing copies it back in (`write_debug_data`)
    ///
    /// Original directory locations are stored in ctx for zeroing actual data regions.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if the PE has no optional header or writing fails.
    fn write_optional_header(&self, ctx: &mut WriteContext) -> Result<()> {
        ctx.optional_header_offset = ctx.pos();

        let view = self.assembly.view();
        let pe = view.file().pe();

        // Clone and modify the optional header
        let mut optional_header = pe
            .optional_header
            .clone()
            .ok_or_else(|| Error::LayoutFailed("No optional header in PE file".to_string()))?;

        // Store original debug directory location for zeroing the data region later
        if let Some(debug_dir) = pe.get_data_directory(DataDirectoryType::Debug) {
            if debug_dir.virtual_address != 0 && debug_dir.size != 0 {
                ctx.original_debug_dir = Some((debug_dir.virtual_address, debug_dir.size));
            }
        }

        // Store original certificate directory location for zeroing the data region later
        // Note: Certificate table uses file offset (not RVA) in the virtual_address field
        if let Some(cert_dir) = pe.get_data_directory(DataDirectoryType::CertificateTable) {
            if cert_dir.virtual_address != 0 && cert_dir.size != 0 {
                ctx.original_certificate_dir = Some((cert_dir.virtual_address, cert_dir.size));
            }
        }

        // Zero out CertificateTable - signature is invalid after modification
        optional_header
            .data_directories
            .update_entry(DataDirectoryType::CertificateTable, 0, 0);

        // Zero out Debug directory - debug info becomes invalid after modification
        optional_header
            .data_directories
            .update_entry(DataDirectoryType::Debug, 0, 0);

        // Write using the struct's write_to method
        optional_header.write_to(ctx)?;

        Ok(())
    }

    /// Writes the section table.
    ///
    /// Writes all section headers. Fields that change (VirtualAddress,
    /// SizeOfRawData, PointerToRawData) are fixed up later in apply_fixups.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    fn write_section_table(&self, ctx: &mut WriteContext) -> Result<()> {
        ctx.section_table_offset = ctx.pos();

        let view = self.assembly.view();
        let pe = view.file().pe();

        // Write each section header and track its position
        for section in &pe.sections {
            let header_offset = ctx.pos();

            // Write the section header
            section.write_to(ctx)?;

            // Record section info for later fixup
            ctx.sections.push(SectionWriteInfo {
                name: section.name.clone(),
                characteristics: section.characteristics,
                header_offset,
                data_offset: None,
                rva: None,
                data_size: None,
                raw_size: None,
                removed: false,
            });
        }

        Ok(())
    }

    /// Writes the IAT (Import Address Table) at the start of .text section.
    ///
    /// Builds the complete import list (mscoree.dll first, then any native imports)
    /// and writes the IAT content directly. The IAT is placed at the very start of
    /// .text section as required by .NET PE format.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if building imports or writing fails.
    fn write_iat(&self, ctx: &mut WriteContext) -> Result<()> {
        ctx.iat_offset = ctx.pos();

        // Build complete import list: mscoree.dll first, then preserved + new imports
        let imports = self.build_import_list(ctx)?;

        // Calculate IAT size
        let iat_size = imports.iat_byte_size(ctx.is_pe32_plus)?;

        if iat_size == 0 {
            // No imports - write minimal placeholder (shouldn't happen for .NET)
            let zeros = [0u8; 8];
            ctx.write(&zeros)?;
            ctx.iat_size = 8;
        } else {
            // Calculate where import table will be written (needed for string RVA calculation)
            // This is a forward reference - we'll write the import table after metadata
            // For now, use a placeholder RVA that will be corrected when we know the final position
            // The IAT content depends on import_table_rva for hint/name string references
            //
            // Since we don't know import_table_rva yet, we store the imports and build IAT
            // later as part of write_import_data, then patch the IAT offset.
            //
            // Alternative: write zeros now, then patch in fixup phase
            let zeros = vec![0u8; iat_size];
            ctx.write(&zeros)?;
            ctx.iat_size = iat_size as u64;
        }

        // Store imports for use in write_import_data
        ctx.pending_imports = Some(imports);

        Ok(())
    }

    /// Builds the complete import list for the assembly.
    ///
    /// The import list is built by merging:
    /// 1. mscoree.dll with _CorExeMain/_CorDllMain (always first)
    /// 2. Original imports from the source PE, but mscoree.dll's entry point
    /// 3. User-added imports from assembly changes, but those already imported
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context (used for PE format detection)
    ///
    /// # Returns
    ///
    /// A `NativeImports` containing all imports with mscoree.dll first.
    ///
    /// # Errors
    ///
    /// When the original import table cannot be read in full, or an import cannot be held
    /// (an empty name, ordinal 0, the same function imported twice): the table written would
    /// lack it.
    fn build_import_list(&self, ctx: &WriteContext) -> Result<NativeImports> {
        let view = self.assembly.view();
        let pe = view.file().pe();
        if let Some(error) = &pe.import_error {
            return Err(Error::LayoutFailed(format!(
                "{error}, so it cannot be written back"
            )));
        }

        let is_entry_point = |dll: &str, function: Option<&str>| {
            dll.eq_ignore_ascii_case("mscoree.dll")
                && matches!(function, Some("_CorExeMain" | "_CorDllMain"))
        };
        let add = |imports: &mut NativeImports, dll: &str, import: &Import| -> Result<()> {
            imports.add_dll(dll)?;
            match (&import.name, import.ordinal) {
                (Some(name), _) => imports.add_function(dll, name),
                (None, Some(ordinal)) => imports.add_function_by_ordinal(dll, ordinal),
                (None, None) => Err(Error::LayoutFailed(format!(
                    "an import from {dll} has neither a name nor an ordinal"
                ))),
            }
        };

        // Collect the original imports, but mscoree.dll's entry point, which is written first
        let mut other_imports = NativeImports::new();
        other_imports.set_pe_format(ctx.is_pe32_plus);
        for import in &pe.imports {
            if !is_entry_point(&import.dll, import.name.as_deref()) {
                add(&mut other_imports, &import.dll, import)?;
            }
        }

        // Add user-specified imports from changes, but what is already imported
        let new_imports = self.assembly.changes().native_imports().native();
        for desc in new_imports.descriptors() {
            for func in &desc.functions {
                let imported = other_imports.descriptors().any(|existing| {
                    existing.dll_name == desc.dll_name
                        && existing.functions.iter().any(|f| {
                            f.name == func.name
                                && (func.name.is_some() || f.ordinal == func.ordinal)
                        })
                });
                if !imported && !is_entry_point(&desc.dll_name, func.name.as_deref()) {
                    add(&mut other_imports, &desc.dll_name, func)?;
                }
            }
        }

        // Build final import list with mscoree.dll FIRST
        let mut final_imports = NativeImports::new();
        final_imports.set_pe_format(ctx.is_pe32_plus);

        // Determine entry point function based on PE characteristics
        let is_dll = view
            .file()
            .header()
            .characteristics
            .contains(PeCharacteristics::DLL);
        let entry_fn = if is_dll { "_CorDllMain" } else { "_CorExeMain" };

        // Add mscoree.dll first (required for .NET)
        final_imports.add_dll("mscoree.dll")?;
        final_imports.add_function("mscoree.dll", entry_fn)?;

        // Add all other imports after mscoree.dll
        for desc in other_imports.descriptors() {
            for func in &desc.functions {
                add(&mut final_imports, &desc.dll_name, func)?;
            }
        }

        Ok(final_imports)
    }

    /// Checks if this assembly is IL-only (no native code).
    ///
    /// Examines the COMIMAGE_FLAGS_ILONLY flag in the COR20 header.
    ///
    /// # Returns
    ///
    /// `true` if the assembly contains only managed IL code, `false` if it has native code.
    fn is_il_only(&self) -> bool {
        let cor20 = self.assembly.view().cor20header();
        cor20.flags.contains(Cor20Flags::IL_ONLY)
    }

    /// Checks if this is a DLL (not an EXE).
    ///
    /// Examines the IMAGE_FILE_DLL flag in the COFF characteristics.
    ///
    /// # Returns
    ///
    /// `true` if the assembly is a DLL, `false` if it's an EXE.
    fn is_dll(&self) -> bool {
        self.assembly
            .view()
            .file()
            .header()
            .characteristics
            .contains(PeCharacteristics::DLL)
    }

    /// Checks if this assembly needs native import table entries.
    ///
    /// Returns `true` if the original PE had an import table, whatever of it could be read,
    /// or if the user has added new native imports. .NET Core assemblies compiled
    /// for x64 typically have no IAT, no import table, and no native entry point;
    /// adding these unconditionally triggers CoreCLR's `CheckILOnly` validation
    /// which requires matching base relocations.
    fn needs_native_imports(&self) -> bool {
        let view = self.assembly.view();

        // Check if original PE had an import table: the loader goes by its RVA, whatever its
        // size says (BitMono writes 0)
        if view
            .file()
            .pe()
            .get_data_directory(DataDirectoryType::ImportTable)
            .is_some_and(|directory| directory.virtual_address != 0)
        {
            return true;
        }

        // Check if user has added any native imports
        let user_imports = self.assembly.changes().native_imports().native();
        if !user_imports.is_empty() {
            return true;
        }

        false
    }

    /// Writes the COR20 (CLR) header.
    ///
    /// Clones the original COR20 header and zeroes the strong name signature
    /// (invalidated by modifications). MetaData RVA/Size are fixed up later.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    fn write_cor20_header(&self, ctx: &mut WriteContext) -> Result<()> {
        ctx.cor20_header_offset = ctx.pos();

        let view = self.assembly.view();

        // Clone and modify the COR20 header
        let mut cor20_header = *view.cor20header();

        // Zero strong name signature - invalidated by modifications
        cor20_header.strong_name_signature_rva = 0;
        cor20_header.strong_name_signature_size = 0;

        // Write using the struct's write_to method
        // MetaData RVA and Size will be fixed up later in apply_fixups
        // Entry point token remapping is also handled in fixups (after the token remap is built)
        cor20_header.write_to(ctx)?;

        Ok(())
    }

    /// Writes method bodies to the output.
    ///
    /// Copies original method bodies and appends new method bodies from changes.
    /// Handles IL token patching for userstring remapping and metadata token updates.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    /// * `changes` - The assembly changes containing new method bodies
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if reading source data or writing fails.
    fn write_method_bodies(&self, ctx: &mut WriteContext, changes: &AssemblyChanges) -> Result<()> {
        let view = self.assembly.view();
        let file = view.file();

        // Copy original method bodies individually (unless configured to skip them)
        // This explicitly copies ONLY method bodies, not FieldRVA data or other content
        // that might be interspersed in the same region.
        if !self.config.skip_original_method_bodies {
            if let Some(tables) = view.tables() {
                if let Some(method_table) = tables.table::<MethodDefRaw>() {
                    let deleted_method_rids: HashSet<u32> = changes
                        .get_table_modifications(TableId::MethodDef)
                        .map(|mods| mods.deleted_rids().collect())
                        .unwrap_or_default();

                    // Track RVAs we've already written to avoid duplicates.
                    // Multiple MethodDef entries can share the same RVA if they have
                    // identical IL bodies - we only need to write each unique body once.
                    let mut written_rvas: HashSet<u32> = HashSet::new();

                    for row in method_table {
                        let row = row?;
                        if deleted_method_rids.contains(&row.rid) {
                            continue;
                        }

                        let original_rva = row.rva;
                        if original_rva == 0 {
                            continue; // Abstract/external method, no body
                        }

                        // Skip placeholder RVAs - these method bodies are stored in
                        // changes.method_bodies() and will be written separately below.
                        // This happens when cleanup patches a method body and stores it
                        // with a placeholder RVA.
                        if original_rva >= METHOD_BODY_PLACEHOLDER_BASE {
                            continue;
                        }

                        // Skip if we've already written a body at this RVA.
                        // The RVA mapping was already recorded on first write.
                        if written_rvas.contains(&original_rva) {
                            continue;
                        }
                        written_rvas.insert(original_rva);

                        let code_type = MethodImplCodeType::from_impl_flags(row.impl_flags);
                        let is_native = code_type.contains(MethodImplCodeType::NATIVE);

                        if is_native || code_type.contains(MethodImplCodeType::RUNTIME) {
                            // Native/runtime methods contain x86/x64 machine code, not CIL.
                            // Copy the raw bytes as-is. Size is determined by decoding
                            // x86 instructions to find the function's RET instruction.
                            #[cfg(feature = "x86")]
                            {
                                // Clamp the scan window to the section containing the stub,
                                // and to an absolute ceiling. Handing the decoder "everything
                                // from here to EOF" let a single native method absorb the rest
                                // of the input file into the output as one body, and made the
                                // decode cost proportional to file size rather than to the stub.
                                let section = file.section_bounded(original_rva as usize)?;
                                let available = section.len().min(MAX_NATIVE_BODY_SCAN_BYTES);
                                let scan_data = section.get(..available).unwrap_or(section);

                                let body_size = x86_native_body_size(scan_data, file.pe().is_64bit);

                                if body_size == 0 || body_size >= available {
                                    // Either no function end was found, or the decode ran to the
                                    // clamp — in both cases the extent is unknown. Emitting the
                                    // row anyway leaves its RVA unmapped, and the fallback
                                    // resolution maps an unmapped RVA to *itself*, so the
                                    // method would point at whatever now occupies that offset in
                                    // the relaid-out file.
                                    return Err(Error::LayoutFailed(format!(
                                        "native method body at RVA 0x{original_rva:08X} has no \
                                         determinable extent (decoded {body_size} of {available} \
                                         bytes); refusing to emit a row with an unresolvable RVA"
                                    )));
                                }

                                let body_data = scan_data.get(..body_size).unwrap_or(scan_data);

                                // Native code needs 4-byte alignment for consistency
                                ctx.align_to_4_with_padding()?;

                                let new_rva = ctx.current_rva();
                                ctx.method_body_rva_map.insert(original_rva, new_rva);
                                ctx.write(body_data)?;
                            }
                        } else {
                            // CIL method - parse, remap tokens, and rebuild
                            let available_data = file.section_bounded(original_rva as usize)?;

                            let rebuilt = rebuild_method_body(
                                available_data,
                                Token::from_parts(TableId::MethodDef, row.rid),
                                &ctx.tokens,
                                &ctx.heap_remapping.userstrings,
                                None,
                            )?;

                            // Fat method headers require 4-byte alignment (ECMA-335 §II.25.4.2)
                            let rebuilt_is_fat = rebuilt.first().is_some_and(|&b| (b & 0x3) == 0x3);
                            if rebuilt_is_fat {
                                ctx.align_to_4_with_padding()?;
                            }

                            let new_rva = ctx.current_rva();
                            ctx.method_body_rva_map.insert(original_rva, new_rva);
                            ctx.write(&rebuilt)?;
                        }
                    }
                }
            }
        }

        // The surviving MethodDef row each new body is the body of, by its placeholder RVA.
        // A body no surviving row has is dead and is not written: its method was deleted, or
        // regenerated again under a newer placeholder, and it may name rows deleted with it.
        let mut owners: HashMap<u32, Token> = HashMap::new();
        let mut own = |rid: u32, row: &TableDataOwned| {
            if let TableDataOwned::MethodDef(method) = row {
                if method.rva >= METHOD_BODY_PLACEHOLDER_BASE {
                    owners
                        .entry(method.rva)
                        .or_insert_with(|| Token::from_parts(TableId::MethodDef, rid));
                }
            }
        };
        match changes.get_table_modifications(TableId::MethodDef) {
            Some(TableModifications::Replaced(rows)) => {
                for (rid, row) in (1u32..).zip(rows) {
                    own(rid, row);
                }
            }
            Some(TableModifications::Sparse {
                operations,
                deleted_rows,
                ..
            }) => {
                // The last operation on a row is the row the write emits.
                let mut last: BTreeMap<u32, &TableDataOwned> = BTreeMap::new();
                for op in operations {
                    if let Operation::Insert(rid, row) | Operation::Update(rid, row) = &op.operation
                    {
                        last.insert(*rid, row);
                    }
                }
                for (rid, row) in last {
                    if !deleted_rows.contains(&rid) {
                        own(rid, row);
                    }
                }
            }
            None => {}
        }

        // Write new method bodies (sorted by placeholder RVA)
        let mut bodies: Vec<_> = changes.method_bodies().collect();
        bodies.sort_by_key(|(placeholder, _)| *placeholder);

        for (placeholder_rva, body_bytes) in bodies {
            let Some(&owner) = owners.get(&placeholder_rva) else {
                continue;
            };
            // A stored body's `ldstr` operands name strings by their input offsets (new
            // strings carry placeholders instead), so they move with the heap as the input
            // bodies' do.
            let rebuilt = rebuild_method_body(
                body_bytes,
                owner,
                &ctx.tokens,
                &ctx.heap_remapping.userstrings,
                Some(changes),
            )?;

            // Fat method headers require 4-byte alignment (ECMA-335 §II.25.4.2)
            let rebuilt_is_fat = rebuilt.first().is_some_and(|&b| (b & 0x3) == 0x3);
            if rebuilt_is_fat {
                ctx.align_to_4_with_padding()?;
            }

            let actual_rva = ctx.current_rva();
            ctx.method_body_rva_map.insert(placeholder_rva, actual_rva);
            ctx.write(&rebuilt)?;
        }

        Ok(())
    }

    /// Writes the CLR resources section.
    ///
    /// This section contains embedded managed resources accessed via
    /// `Assembly.GetManifestResourceStream()`. The section is pointed to by the
    /// COR20 header's resource_rva/resource_size fields.
    ///
    /// Each resource entry is stored as:
    /// - 4-byte little-endian length prefix
    /// - Actual resource data bytes
    ///
    /// The ManifestResource table's offset_field contains offsets relative to the
    /// start of this section.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    /// * `changes` - The assembly changes containing new resource data
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if reading source data or writing fails.
    fn write_resource_data(&self, ctx: &mut WriteContext, changes: &AssemblyChanges) -> Result<()> {
        let view = self.assembly.view();
        let file = view.file();
        let cor20 = view.cor20header();

        // Track the start of the resources section
        ctx.resource_data_offset = ctx.pos();

        // Copy original resources, compacting out deleted ManifestResource entries.
        // Each resource in the CLR resource section is: [4-byte LE length][data].
        // ManifestResource.offset_field points to the start of the length prefix.
        if cor20.resource_rva != 0 && cor20.resource_size != 0 {
            let original_data =
                file.rva_slice(cor20.resource_rva as usize, cor20.resource_size as usize)?;

            // Check if any ManifestResource rows have been deleted. If not, fast-path:
            // copy everything as-is.
            let has_deletions = view
                .tables()
                .and_then(|t| t.table::<ManifestResourceRaw>())
                .is_some_and(|table| {
                    table.iter().filter_map(skip_unreadable).any(|row| {
                        // Only embedded resources (implementation.row == 0) have data
                        // in this section.
                        row.implementation.row == 0
                            && changes.is_row_deleted(TableId::ManifestResource, row.rid)
                    })
                });

            if has_deletions {
                // Compact: copy only surviving embedded resources.
                if let Some(table) = view.tables().and_then(|t| t.table::<ManifestResourceRaw>()) {
                    let mut new_offset = 0u32;
                    for row in table {
                        let row = row?;
                        // External resources don't have data in this section
                        if row.implementation.row != 0 {
                            continue;
                        }

                        let old_offset = row.offset_field;
                        let entry_start = old_offset as usize;

                        // Read the 4-byte length prefix
                        let len_end = match entry_start.checked_add(4) {
                            Some(v) => v,
                            None => continue,
                        };
                        if len_end > original_data.len() {
                            continue;
                        }
                        let len_slice = match original_data.get(entry_start..len_end) {
                            Some(s) => s,
                            None => continue,
                        };
                        let len_arr: [u8; 4] = match len_slice.try_into() {
                            Ok(a) => a,
                            Err(_) => continue,
                        };
                        let data_len = u32::from_le_bytes(len_arr) as usize;
                        let entry_total = match data_len.checked_add(4) {
                            Some(v) => v,
                            None => continue,
                        };

                        let entry_end = match entry_start.checked_add(entry_total) {
                            Some(v) => v,
                            None => continue,
                        };
                        if entry_end > original_data.len() {
                            continue;
                        }

                        // Skip deleted resources
                        if changes.is_row_deleted(TableId::ManifestResource, row.rid) {
                            continue;
                        }

                        // Write surviving resource and track offset remapping
                        let entry_data = match original_data.get(entry_start..entry_end) {
                            Some(s) => s,
                            None => continue,
                        };
                        ctx.write(entry_data)?;
                        ctx.resource_offset_remap.insert(old_offset, new_offset);
                        new_offset =
                            new_offset.checked_add(entry_total as u32).ok_or_else(|| {
                                Error::LayoutFailed("Resource offset overflow".to_string())
                            })?;
                    }
                }
            } else {
                // No deletions — copy all original resources as-is
                ctx.write(&original_data)?;
            }
        }

        // Append new resources from changes
        // Note: The offsets in ManifestResource.offset_field are calculated based on
        // the position where resources are stored in changes.resource_data, which
        // accounts for original resource size via store_resource_data's offset calculation.
        // However, for newly added resources, we need to adjust offsets based on the
        // original resource size. This is handled by the offset calculation in
        // AssemblyChanges::store_resource_data - the offset returned is relative to
        // the START of the new resource data section, so we need to add the original
        // resource size when writing the table.
        if changes.has_resource_data() {
            ctx.write(changes.resource_data_bytes())?;
        }

        // Calculate total size
        ctx.resource_data_size = ctx
            .pos()
            .checked_sub(ctx.resource_data_offset)
            .ok_or_else(|| Error::LayoutFailed("Resource data size underflow".to_string()))?;

        Ok(())
    }

    /// Writes the complete metadata section.
    ///
    /// The metadata section layout is:
    /// 1. Metadata root header (signature, version, stream count)
    /// 2. Stream headers (offsets and sizes, all relative to metadata root)
    /// 3. #~ stream (tables)
    /// 4. #Strings heap
    /// 5. #US heap
    /// 6. #GUID heap
    /// 7. #Blob heap
    ///
    /// Headers have fixed structure - we write them with placeholders first,
    /// then write content, then fixup the header fields with actual values.
    ///
    /// The key insight: heaps produce offset remapping during streaming writes.
    /// Tables contain heap references that need patching. So we:
    /// 1. Write metadata root header (with placeholder stream offsets/sizes)
    /// 2. Write tables stream (table data written sequentially)
    /// 3. Write heaps → get remapping
    /// 4. Patch table rows in-place with new heap offsets
    /// 5. Fixup metadata root header with final stream offsets/sizes
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    /// * `changes` - The assembly changes containing modifications
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if any phase of metadata writing fails.
    fn write_metadata(&self, ctx: &mut WriteContext, changes: &AssemblyChanges) -> Result<()> {
        let view = self.assembly.view();
        let root = view.metadata_root();

        // Note: precompute_heap_offsets is called earlier (before method bodies)
        // so that ChangeRefs are resolved for IL placeholder patching.

        // PHASE 1: Write metadata root header with placeholder stream headers
        let metadata_root_offset = ctx.pos();
        // We'll track where stream headers start so we can patch them later
        let stream_headers_offset = self.write_metadata_root_header(ctx, root)?;

        // PHASE 2: Write tables stream (ChangeRefs are now resolved!)
        ctx.align_to_4();
        ctx.tables_stream_offset = ctx.pos();
        self.write_tables_stream(ctx, changes)?;

        // PHASE 3: Write heaps - this populates ctx.heap_remapping
        // Note: ChangeRefs are already resolved, so this just writes the data
        self.write_heaps(ctx, changes)?;

        // PHASE 4: Patch table rows after heaps are written
        // This handles old→new heap offset remapping (from deduplication)
        // ChangeRef resolution is no longer needed here since we pre-computed offsets
        self.patch_tables_after_heaps(ctx, changes)?;

        // PHASE 5: Fixup metadata root header with final stream offsets/sizes
        fixup_metadata_stream_headers(ctx, metadata_root_offset, stream_headers_offset)?;

        // Update metadata size
        ctx.metadata_size = ctx
            .pos()
            .checked_sub(metadata_root_offset)
            .ok_or_else(|| Error::LayoutFailed("Metadata size underflow".to_string()))?;

        // Note: Table ChangeRefs are resolved earlier (before method bodies)
        // to support methods with local variable signatures

        Ok(())
    }

    /// Writes the metadata root header with placeholder stream headers.
    ///
    /// Creates a modified root header with 5 standard stream headers containing
    /// placeholder values (offset=0, size=0). These are patched later by
    /// `fixup_metadata_stream_headers` after all streams are written.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    /// * `root` - The original metadata root to clone
    ///
    /// # Returns
    ///
    /// The file offset where stream headers start (for later fixup).
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    fn write_metadata_root_header(&self, ctx: &mut WriteContext, root: &Root) -> Result<u64> {
        let _ = self; // Method signature kept for consistency
                      // Create a modified root with placeholder stream headers
        let placeholder_streams: Vec<StreamHeader> = ["#~", "#Strings", "#US", "#GUID", "#Blob"]
            .iter()
            .map(|name| StreamHeader {
                offset: 0, // Placeholder - will be patched later
                size: 0,   // Placeholder - will be patched later
                name: (*name).to_string(),
            })
            .collect();

        let version_padded_len = root.version_field_size();
        let version_len_u32 = u32::try_from(version_padded_len).map_err(|_| {
            Error::LayoutFailed(format!(
                "Version length {version_padded_len} exceeds u32 range"
            ))
        })?;
        let modified_root = Root {
            signature: root.signature,
            major_version: root.major_version,
            minor_version: root.minor_version,
            reserved: root.reserved,
            length: version_len_u32,
            version: root.version.clone(),
            flags: root.flags,
            stream_number: 5, // We always have 5 streams
            stream_headers: placeholder_streams,
        };

        // Calculate where stream headers will start (after fixed root header)
        // sig(4) + major(2) + minor(2) + reserved(4) + length(4) + version(padded) + flags(2) + count(2)
        let fixed_header_size = 20usize
            .checked_add(version_padded_len)
            .ok_or_else(|| Error::LayoutFailed("Header size overflow".to_string()))?;
        let stream_headers_offset = ctx
            .pos()
            .checked_add(fixed_header_size as u64)
            .ok_or_else(|| Error::LayoutFailed("Stream headers offset overflow".to_string()))?;

        // Write the full root header using its write_to method
        modified_root.write_to(ctx)?;

        Ok(stream_headers_offset)
    }

    /// Patches table rows in-place after heaps are written.
    ///
    /// This handles two types of patching:
    /// 1. Old→new heap offset remapping (from streaming heap deduplication)
    /// 2. ChangeRef placeholder resolution (for newly added heap entries)
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context with heap remapping data
    /// * `changes` - The assembly changes for ChangeRef lookup
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if the assembly has no tables or read/write operations fail.
    fn patch_tables_after_heaps(
        &self,
        ctx: &mut WriteContext,
        changes: &AssemblyChanges,
    ) -> Result<()> {
        let view = self.assembly.view();
        let tables = view
            .tables()
            .ok_or_else(|| Error::LayoutFailed("No tables found".to_string()))?;

        // Calculate new row counts for each table (needed for output table info)
        let mut new_row_counts: HashMap<TableId, u32> = HashMap::new();
        let mut valid = tables.valid;

        for table_id in TableId::iter() {
            let original_count = tables.table_row_count(table_id);
            if let Some(table_mod) = changes.get_table_modifications(table_id) {
                let mut new_count = self.calculate_table_row_count(table_id, table_mod)?;
                // Subtract deduplicated StandAloneSig entries
                if table_id == TableId::StandAloneSig {
                    #[allow(clippy::cast_possible_truncation)]
                    let skip_len = ctx.standalonesig_skip.len() as u32;
                    new_count = new_count.saturating_sub(skip_len);
                }
                new_row_counts.insert(table_id, new_count);
                if new_count > 0 {
                    valid |= 1u64 << (table_id as u64);
                } else {
                    valid &= !(1u64 << (table_id as u64));
                }
            } else if original_count > 0 {
                // Unmodified table - keep original count (minus dedup for StandAloneSig)
                let mut count = original_count;
                if table_id == TableId::StandAloneSig {
                    #[allow(clippy::cast_possible_truncation)]
                    let skip_len = ctx.standalonesig_skip.len() as u32;
                    count = count.saturating_sub(skip_len);
                }
                new_row_counts.insert(table_id, count);
            }
        }

        // Create output table info with new row counts (same as in write_tables_stream)
        // This ensures we use the correct row sizes for reading the output
        // Row counts first, then heap index widths derived from the heaps actually written.
        // Both must reflect the *output*: `with_modified_row_counts` copies the input's heap
        // widths verbatim, so without the second step a writer that appends past 0xFFFF keeps
        // emitting 2-byte indices and every offset beyond it is masked.
        let output_table_info = {
            let with_rows = tables
                .info
                .with_modified_row_counts(new_row_counts.iter().map(|(k, v)| (*k, *v)));
            Arc::new(match ctx.output_heap_sizes {
                Some((strings, guids, blobs)) => {
                    with_rows.with_modified_heap_sizes(strings, guids, blobs)
                }
                None => with_rows,
            })
        };

        // Calculate where table data starts (after tables stream header)
        let header_size = (valid.count_ones() as usize)
            .checked_mul(4)
            .and_then(|v| v.checked_add(24))
            .ok_or_else(|| Error::LayoutFailed("Tables header size overflow".to_string()))?;
        let mut table_data_offset = ctx
            .tables_stream_offset
            .checked_add(header_size as u64)
            .ok_or_else(|| Error::LayoutFailed("Tables data offset overflow".to_string()))?;

        // Clone remapping to avoid borrow issues
        let strings_remap = ctx.heap_remapping.strings.clone();
        let blobs_remap = ctx.heap_remapping.blobs.clone();
        let guids_remap = ctx.heap_remapping.guids.clone();

        for table_id in TableId::iter() {
            if valid & (1u64 << (table_id as u64)) == 0 {
                continue;
            }

            // Get the output row count
            let output_row_count = new_row_counts.get(&table_id).copied().unwrap_or(0);

            // Use output table info row size since we're reading from output
            let row_size = calculate_table_row_size(table_id, &output_table_info) as usize;

            // Patch each row in the output table
            for output_idx in 0..output_row_count as usize {
                let row_off_within = (output_idx as u64)
                    .checked_mul(row_size as u64)
                    .ok_or_else(|| Error::LayoutFailed("Row offset overflow".to_string()))?;
                let row_offset = table_data_offset
                    .checked_add(row_off_within)
                    .ok_or_else(|| Error::LayoutFailed("Row offset overflow".to_string()))?;
                let mut row_buffer = vec![0u8; row_size];
                ctx.output.read_at(row_offset, &mut row_buffer)?;

                // First: resolve ChangeRef placeholders (for newly added heap entries)
                // These are heap references that were written before heaps existed
                Self::patch_row_change_ref_placeholders(
                    &mut row_buffer,
                    table_id,
                    &output_table_info,
                    changes,
                )?;

                // Second: apply old→new heap offset remapping (from deduplication)
                // This applies to ALL rows, including updated ones. ChangeRef placeholders
                // resolve to NEW heap offsets, which won't appear in the remapping (since
                // remapping only contains old->new mappings for deduplicated entries).
                // Updated rows may still have original heap offsets in fields that weren't
                // modified (e.g., a MethodDef update that only changes RVA but not name).
                if ctx.heap_remapping.has_changes() {
                    patch_row_heap_refs(
                        table_id,
                        &mut row_buffer,
                        &output_table_info,
                        &strings_remap,
                        &blobs_remap,
                        &guids_remap,
                    )?;
                }

                ctx.write_at(row_offset, &row_buffer)?;
            }

            let table_bytes = u64::from(output_row_count)
                .checked_mul(row_size as u64)
                .ok_or_else(|| Error::LayoutFailed("Table size overflow".to_string()))?;
            table_data_offset = table_data_offset
                .checked_add(table_bytes)
                .ok_or_else(|| Error::LayoutFailed("Table data offset overflow".to_string()))?;
        }

        Ok(())
    }

    /// Patches ChangeRef placeholders in a table row buffer.
    ///
    /// When tables are written before heaps, heap references for newly added entries
    /// contain ChangeRef placeholder values. After heaps are written and ChangeRefs
    /// are resolved, this function patches those placeholders to actual offsets.
    ///
    /// # Arguments
    ///
    /// * `row_buffer` - The raw bytes of the table row to patch
    /// * `table_id` - The table type (determines which fields are heap references)
    /// * `table_info` - Table size information for field offset calculation
    /// * `changes` - The assembly changes for ChangeRef lookup
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::LayoutFailed`] if a resolved heap offset does not fit the index
    /// width the emitted `HeapSizes` byte declares.
    fn patch_row_change_ref_placeholders(
        row_buffer: &mut [u8],
        table_id: TableId,
        table_info: &TableInfoRef,
        changes: &AssemblyChanges,
    ) -> Result<()> {
        // Get heap field positions using the centralized schema
        let heap_fields = get_heap_fields(table_id, table_info);

        for field in heap_fields {
            let Some(field_end) = field.offset.checked_add(field.size) else {
                continue;
            };
            if field_end > row_buffer.len() {
                continue;
            }

            let Some(field_slice) = row_buffer.get(field.offset..field_end) else {
                continue;
            };

            // Read the field value
            let value = if field.size == 4 {
                let Ok(arr) = <[u8; 4]>::try_from(field_slice) else {
                    continue;
                };
                u32::from_le_bytes(arr)
            } else {
                let Ok(arr) = <[u8; 2]>::try_from(field_slice) else {
                    continue;
                };
                u32::from(u16::from_le_bytes(arr))
            };

            // Check if it's a placeholder
            if ChangeRef::is_heap_placeholder(value) {
                if let Some(change_ref) = changes.lookup_by_placeholder(value) {
                    if let Some(resolved) = change_ref.offset() {
                        // Write the resolved value back
                        let Some(field_slice_mut) = row_buffer.get_mut(field.offset..field_end)
                        else {
                            continue;
                        };
                        if field.size == 4 {
                            field_slice_mut.copy_from_slice(&resolved.to_le_bytes());
                        } else {
                            // A 2-byte heap index cannot represent an offset past 0xFFFF.
                            //
                            // Masking to 16 bits would not produce a broken file — it would
                            // produce a *valid-looking* one whose names, signatures and
                            // attribute blobs point at arbitrary earlier heap positions,
                            // deterministically modulo 0x10000, and an analyst consumes those
                            // attributions as fact. Reaching this means the emitted HeapSizes
                            // byte disagrees with the heap that was actually written, which is
                            // a layout bug and must not be silently encoded into the output.
                            let small_value = u16::try_from(resolved).map_err(|_| {
                                Error::LayoutFailed(format!(
                                    "heap offset 0x{resolved:X} exceeds the 2-byte index width \
                                     declared by HeapSizes; the output heap grew past 0xFFFF but \
                                     the index width was not promoted"
                                ))
                            })?;
                            field_slice_mut.copy_from_slice(&small_value.to_le_bytes());
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Estimates the size of the metadata root header.
    ///
    /// Calculates the approximate size needed for the metadata root header including
    /// the version string (aligned to 4 bytes) and stream headers.
    ///
    /// # Returns
    ///
    /// The estimated header size in bytes.
    fn estimate_metadata_header_size(&self) -> usize {
        let view = self.assembly.view();
        let root = view.metadata_root();

        // Base header: signature (4) + major (2) + minor (2) + reserved (4) + version_length (4)
        let base_size: usize = 16;
        let aligned_version = root.version_field_size();
        // Flags (2) + stream count (2)
        let flags_and_count: usize = 4;
        // Stream headers: each is offset (4) + size (4) + name (variable, 4-byte aligned)
        // Estimate 5 streams max with ~12 bytes each for names
        let stream_headers: usize = 5 * (8 + 12);

        base_size
            .saturating_add(aligned_version)
            .saturating_add(flags_and_count)
            .saturating_add(stream_headers)
    }

    /// Writes all heaps using streaming writers.
    ///
    /// Writes the four metadata heaps in order: #Strings, #US, #GUID, #Blob.
    /// Each heap is aligned to 4 bytes and uses streaming deduplication.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and heap mappings
    /// * `changes` - The assembly changes containing heap modifications
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if heap streaming fails.
    fn write_heaps(&self, ctx: &mut WriteContext, changes: &AssemblyChanges) -> Result<()> {
        let view = self.assembly.view();

        // Default empty heap data
        let empty_strings: &[u8] = &[0u8];
        let empty_blob: &[u8] = &[0u8];
        let empty_guid: &[u8] = &[];
        let empty_us: &[u8] = &[0u8];

        // Get source heap data
        let strings_data: &[u8] = changes
            .string_heap_changes
            .replacement_heap()
            .map(Vec::as_slice)
            .or_else(|| view.strings().map(Strings::data))
            .unwrap_or(empty_strings);

        let blob_data: &[u8] = changes
            .blob_heap_changes
            .replacement_heap()
            .map(Vec::as_slice)
            .or_else(|| view.blobs().map(Blob::data))
            .unwrap_or(empty_blob);

        let guid_data: &[u8] = changes
            .guid_heap_changes
            .replacement_heap()
            .map(Vec::as_slice)
            .or_else(|| view.guids().map(Guid::data))
            .unwrap_or(empty_guid);

        let us_data: &[u8] = changes
            .userstring_heap_changes
            .replacement_heap()
            .map(Vec::as_slice)
            .or_else(|| view.userstrings().map(UserStrings::data))
            .unwrap_or(empty_us);

        // Write #Strings heap
        ctx.align_to_4();
        ctx.strings_heap_offset = ctx.pos();
        let strings_result = stream_strings_heap(
            &mut ctx.output,
            ctx.strings_heap_offset,
            strings_data,
            &changes.string_heap_changes,
            &ctx.referenced_string_offsets,
        )?;
        ctx.strings_heap_size = strings_result.bytes_written;
        ctx.heap_remapping.strings = strings_result.remapping;
        ctx.advance(ctx.strings_heap_size);

        // Write #US heap
        ctx.align_to_4();
        ctx.us_heap_offset = ctx.pos();
        let us_result = stream_userstring_heap(
            &mut ctx.output,
            ctx.us_heap_offset,
            us_data,
            &changes.userstring_heap_changes,
            &ctx.referenced_userstring_offsets,
        )?;
        ctx.us_heap_size = us_result.bytes_written;
        ctx.heap_remapping.userstrings = us_result.remapping;
        ctx.advance(ctx.us_heap_size);

        // Write #GUID heap
        ctx.align_to_4();
        ctx.guid_heap_offset = ctx.pos();
        let guid_result = stream_guid_heap(
            &mut ctx.output,
            ctx.guid_heap_offset,
            guid_data,
            &changes.guid_heap_changes,
        )?;
        ctx.guid_heap_size = guid_result.bytes_written;
        ctx.heap_remapping.guids = guid_result.remapping;
        ctx.advance(ctx.guid_heap_size);

        // Write #Blob heap (with signature token remapping if TypeDefs/TypeRefs were deleted)
        ctx.align_to_4();
        ctx.blob_heap_offset = ctx.pos();
        let blob_result = stream_blob_heap(
            &mut ctx.output,
            ctx.blob_heap_offset,
            blob_data,
            &changes.blob_heap_changes,
            &BlobRemap {
                blobs: &ctx.typed_blobs,
                tokens: &ctx.tokens,
                changes,
            },
            &ctx.referenced_blob_offsets,
        )?;
        ctx.blob_heap_size = blob_result.bytes_written;
        ctx.heap_remapping.blobs = blob_result.remapping;
        ctx.advance(ctx.blob_heap_size);

        // Align final position to 4 bytes for proper metadata section end
        ctx.align_to_4();

        Ok(())
    }

    /// Resolves all table row ChangeRefs to their actual metadata tokens.
    ///
    /// Iterates through all table ChangeRefs and resolves unresolved ones to their
    /// final metadata token values (combining table ID and RID).
    ///
    /// # Arguments
    ///
    /// * `changes` - The assembly changes containing table ChangeRefs
    fn resolve_table_change_refs(changes: &AssemblyChanges) {
        for (table_id, rid, change_ref) in changes.all_table_change_refs() {
            if !change_ref.is_resolved() {
                let token = Token::from_parts(table_id, *rid);
                change_ref.resolve_to_token(token);
            }
        }
    }

    /// Writes the tables stream (#~).
    ///
    /// Writes the tables stream header followed by all table data. This writes tables
    /// with original heap references; heap patching happens AFTER heaps are written
    /// via `patch_tables_after_heaps`.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    /// * `changes` - The assembly changes containing table modifications
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if the assembly has no tables or writing fails.
    fn write_tables_stream(&self, ctx: &mut WriteContext, changes: &AssemblyChanges) -> Result<()> {
        let view = self.assembly.view();

        let tables = view
            .tables()
            .ok_or_else(|| Error::LayoutFailed("No tables found in assembly".to_string()))?;

        // Build original row counts map for RID remapping
        let mut original_counts: HashMap<TableId, u32> = HashMap::new();
        for table_id in TableId::iter() {
            let count = tables.table_row_count(table_id);
            if count > 0 {
                original_counts.insert(table_id, count);
            }
        }

        // Build RID remapper for handling row deletions
        let mut remapper =
            RidRemapper::from_changes(changes, &original_counts, self.config.dangling);

        // Calculate new row counts for all tables and build valid bitvector
        let mut valid = tables.valid;
        let mut new_row_counts: HashMap<TableId, u32> = HashMap::new();

        for table_id in TableId::iter() {
            let original_count = tables.table_row_count(table_id);
            if let Some(table_mod) = changes.get_table_modifications(table_id) {
                let mut new_count = self.calculate_table_row_count(table_id, table_mod)?;
                // Subtract deduplicated StandAloneSig entries
                if table_id == TableId::StandAloneSig {
                    #[allow(clippy::cast_possible_truncation)]
                    let skip_len = ctx.standalonesig_skip.len() as u32;
                    new_count = new_count.saturating_sub(skip_len);
                }
                new_row_counts.insert(table_id, new_count);
                if new_count > 0 {
                    valid |= 1u64 << (table_id as u64);
                } else {
                    // Clear bit if table is now empty
                    valid &= !(1u64 << (table_id as u64));
                }
            } else if original_count > 0 {
                // Unmodified table - keep original count (minus dedup for StandAloneSig)
                let mut count = original_count;
                if table_id == TableId::StandAloneSig {
                    #[allow(clippy::cast_possible_truncation)]
                    let skip_len = ctx.standalonesig_skip.len() as u32;
                    count = count.saturating_sub(skip_len);
                }
                new_row_counts.insert(table_id, count);
            }
        }

        // Create output table info with new row counts
        // This recalculates coded index sizes based on new row counts
        // Row counts first, then heap index widths derived from the heaps actually written.
        // Both must reflect the *output*: `with_modified_row_counts` copies the input's heap
        // widths verbatim, so without the second step a writer that appends past 0xFFFF keeps
        // emitting 2-byte indices and every offset beyond it is masked.
        let output_table_info = {
            let with_rows = tables
                .info
                .with_modified_row_counts(new_row_counts.iter().map(|(k, v)| (*k, *v)));
            Arc::new(match ctx.output_heap_sizes {
                Some((strings, guids, blobs)) => {
                    with_rows.with_modified_heap_sizes(strings, guids, blobs)
                }
                None => with_rows,
            })
        };

        // Settle the order of every table the format requires sorted before
        // anything is written: tables written earlier hold references into
        // them (an attribute on a generic parameter, a constraint on it), so
        // where each of their rows lands has to be known first. `SORTED_TABLES`
        // lists a table after the sorted tables its key refers to, so each key
        // is computed with those references already in their final form.
        let fixups = RowFixups::from_context(ctx);
        for &table_id in SORTED_TABLES {
            if valid & (1u64 << (table_id as u64)) == 0 {
                continue;
            }
            let mut rows = Vec::new();
            self.emit_table_rows(
                &fixups,
                table_id,
                &output_table_info,
                changes,
                &remapper,
                &mut |rid, key, _| {
                    rows.push((rid, key.unwrap_or_default()));
                    Ok(())
                },
            )?;
            remapper.set_sort_order(table_id, &rows);
        }
        let sorted = SORTED_TABLES.iter().fold(tables.sorted, |bits, &table_id| {
            bits | (1u64 << (table_id as u64))
        });

        // Write tables stream header using OUTPUT table info
        let mut header_buffer = Vec::new();

        // Reserved (4 bytes)
        header_buffer.write_all(&[0u8; 4])?;
        // Major version
        header_buffer.write_all(&[tables.major_version])?;
        // Minor version
        header_buffer.write_all(&[tables.minor_version])?;
        // HeapSizes
        header_buffer.write_all(&[output_table_info.heap_sizes()])?;
        // Reserved (1 byte, must be 1)
        header_buffer.write_all(&[0x01])?;
        // Valid bitvector
        header_buffer.write_all(&valid.to_le_bytes())?;
        // Sorted bitvector: every table the format requires sorted now is
        header_buffer.write_all(&sorted.to_le_bytes())?;

        // Row counts for each present table
        for table_id in TableId::iter() {
            if valid & (1u64 << (table_id as u64)) != 0 {
                let row_count = new_row_counts.get(&table_id).copied().unwrap_or(0);
                header_buffer.write_all(&row_count.to_le_bytes())?;
            }
        }

        ctx.write(&header_buffer)?;

        // Write table data using unified approach
        for table_id in TableId::iter() {
            if valid & (1u64 << (table_id as u64)) == 0 {
                continue;
            }

            self.write_table_data(
                ctx,
                &fixups,
                table_id,
                &output_table_info,
                changes,
                &remapper,
            )?;
        }

        ctx.tables_stream_size = ctx
            .pos()
            .checked_sub(ctx.tables_stream_offset)
            .ok_or_else(|| Error::LayoutFailed("Tables stream size underflow".to_string()))?;

        Ok(())
    }

    /// Calculates the row count for a table after modifications.
    ///
    /// Computes the final row count by starting with the original count and
    /// adjusting for inserted and deleted rows.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The table to calculate the count for
    /// * `table_mod` - The modifications applied to the table
    ///
    /// # Returns
    ///
    /// The final row count after applying modifications.
    ///
    /// # Errors
    ///
    /// Returns an error if the assembly has no tables.
    fn calculate_table_row_count(
        &self,
        table_id: TableId,
        table_mod: &TableModifications,
    ) -> Result<u32> {
        let view = self.assembly.view();
        let tables = view
            .tables()
            .ok_or_else(|| Error::LayoutFailed("No tables found".to_string()))?;
        let original_count = tables.table_row_count(table_id);

        match table_mod {
            TableModifications::Replaced(rows) => u32::try_from(rows.len()).map_err(|_| {
                Error::LayoutFailed(format!(
                    "Table {:?} row count {} exceeds u32::MAX",
                    table_id,
                    rows.len()
                ))
            }),
            TableModifications::Sparse { operations, .. } => {
                let added_count = operations
                    .iter()
                    .filter(|op| matches!(op.operation, Operation::Insert(_, _)))
                    .count();
                let deleted_count = operations
                    .iter()
                    .filter(|op| matches!(op.operation, Operation::Delete(_)))
                    .count();
                let added = u32::try_from(added_count).map_err(|_| {
                    Error::LayoutFailed(format!(
                        "Table {table_id:?} added count {added_count} exceeds u32::MAX"
                    ))
                })?;
                let deleted = u32::try_from(deleted_count).map_err(|_| {
                    Error::LayoutFailed(format!(
                        "Table {table_id:?} deleted count {deleted_count} exceeds u32::MAX"
                    ))
                })?;
                let total = original_count
                    .checked_add(added)
                    .ok_or_else(|| Error::LayoutFailed("Row count overflow".to_string()))?;
                total
                    .checked_sub(deleted)
                    .ok_or_else(|| Error::LayoutFailed("Row count underflow".to_string()))
            }
        }
    }

    /// Writes one table's rows.
    ///
    /// Rows come from [`emit_table_rows`](Self::emit_table_rows). A table the
    /// format requires sorted is written in its sort order, the order the
    /// remapper was told about in [`write_tables_stream`](Self::write_tables_stream),
    /// so the references other tables hold to its rows already point where
    /// they land; every other table is written as it comes.
    ///
    /// # Errors
    ///
    /// Returns an error if row serialization or writing fails.
    fn write_table_data(
        &self,
        ctx: &mut WriteContext,
        fixups: &RowFixups,
        table_id: TableId,
        output_table_info: &TableInfoRef,
        changes: &AssemblyChanges,
        remapper: &RidRemapper,
    ) -> Result<()> {
        if !SORTED_TABLES.contains(&table_id) {
            return self.emit_table_rows(
                fixups,
                table_id,
                output_table_info,
                changes,
                remapper,
                &mut |_, _, row| ctx.write(row),
            );
        }

        let row_size = calculate_table_row_size(table_id, output_table_info) as usize;
        let mut keys = Vec::new();
        let mut bytes = Vec::new();
        self.emit_table_rows(
            fixups,
            table_id,
            output_table_info,
            changes,
            remapper,
            &mut |_, key, row| {
                keys.push(key.unwrap_or_default());
                bytes.extend_from_slice(row);
                Ok(())
            },
        )?;

        // The same stable sort `set_sort_order` recorded, over the same keys.
        let mut order: Vec<usize> = (0..keys.len()).collect();
        order.sort_by_key(|&index| keys.get(index).copied());
        for index in order {
            let start = index
                .checked_mul(row_size)
                .ok_or_else(|| Error::LayoutFailed("Row offset overflow".to_string()))?;
            let row = bytes
                .get(start..start.saturating_add(row_size))
                .ok_or_else(|| Error::LayoutFailed("Row out of range".to_string()))?;
            ctx.write(row)?;
        }
        Ok(())
    }

    /// Produces a table's rows as they are written, in table order.
    ///
    /// Handles tables with no modifications, fully replaced tables, and sparse
    /// modifications (updates, deletes, inserts). Every row has its references
    /// remapped and its RVAs fixed up, and is handed to `sink` with the RID it
    /// is known by (its original RID, or the RID it was inserted at) and its
    /// [sort key](RowWritable::sort_key).
    ///
    /// # Errors
    ///
    /// Returns an error if row serialization fails or `sink` does.
    fn emit_table_rows(
        &self,
        fixups: &RowFixups,
        table_id: TableId,
        output_table_info: &TableInfoRef,
        changes: &AssemblyChanges,
        remapper: &RidRemapper,
        sink: &mut RowSink<'_>,
    ) -> Result<()> {
        let output_row_size = calculate_table_row_size(table_id, output_table_info) as usize;
        let needs_remapping = remapper.needs_remapping(table_id);
        let mut buffer = vec![0u8; output_row_size];

        // Serializes one row, fixes up its RVAs, and hands it on.
        let mut emit = |rid: u32, row: &dyn RowSource, buffer: &mut Vec<u8>| -> Result<()> {
            let key = row.key(output_table_info)?;
            let mut buf_offset = 0;
            row.write(buffer, &mut buf_offset, rid, output_table_info)?;
            fixups.apply(buffer, table_id);
            sink(rid, key, buffer)
        };

        // Get table modification info (if any)
        let table_mod = changes.get_table_modifications(table_id);

        // Handle fully replaced tables
        if let Some(TableModifications::Replaced(rows)) = table_mod {
            for (idx, row) in rows.iter().enumerate() {
                let rid_idx = idx
                    .checked_add(1)
                    .ok_or_else(|| Error::LayoutFailed("Row index overflow".to_string()))?;
                let rid = u32::try_from(rid_idx).map_err(|_| {
                    Error::LayoutFailed(format!("Row index {rid_idx} exceeds u32 range"))
                })?;

                let mut resolved_row = row.clone();
                resolved_row.resolve_placeholders(changes);
                if needs_remapping {
                    resolved_row.remap_references(remapper)?;
                }
                emit(rid, &resolved_row, &mut buffer)?;
            }
            return Ok(());
        }

        // Extract sparse modification info (deletions, updates, inserts)
        let (deleted_rows, updates, inserts) = match table_mod {
            Some(TableModifications::Sparse {
                operations,
                deleted_rows,
                ..
            }) => {
                // Build update map for O(1) lookup
                let updates: HashMap<u32, &TableDataOwned> = operations
                    .iter()
                    .filter_map(|op| {
                        if let Operation::Update(rid, data) = &op.operation {
                            Some((*rid, data))
                        } else {
                            None
                        }
                    })
                    .collect();

                // Collect inserts sorted by RID
                let mut inserts: Vec<_> = operations
                    .iter()
                    .filter_map(|op| {
                        if let Operation::Insert(rid, data) = &op.operation {
                            Some((*rid, data))
                        } else {
                            None
                        }
                    })
                    .collect();
                inserts.sort_by_key(|(rid, _)| *rid);

                (deleted_rows.clone(), updates, inserts)
            }
            _ => (
                HashSet::<u32>::new(),
                HashMap::<u32, &TableDataOwned>::new(),
                Vec::<(u32, &TableDataOwned)>::new(),
            ),
        };

        // Get the parsed tables for reading original rows
        let tables = self
            .assembly
            .view
            .tables()
            .ok_or_else(|| Error::LayoutFailed("No tables stream".to_string()))?;
        let original_row_count = tables.table_row_count(table_id);

        // Original rows (using parsed table data)
        dispatch_table_type!(table_id, |RawType| {
            if let Some(table) = tables.table::<RawType>() {
                for rid in 1..=original_row_count {
                    // Skip deleted rows
                    if deleted_rows.contains(&rid) {
                        continue;
                    }

                    // Skip StandAloneSig duplicates (deduplication)
                    if table_id == TableId::StandAloneSig
                        && fixups.standalonesig_skip.contains(&rid)
                    {
                        continue;
                    }

                    // Check for updated row data
                    if let Some(row_data) = updates.get(&rid) {
                        let mut resolved_row = (*row_data).clone();
                        resolved_row.resolve_placeholders(changes);
                        if needs_remapping {
                            resolved_row.remap_references(remapper)?;
                        }
                        emit(rid, &resolved_row, &mut buffer)?;
                    } else if let Some(mut row) = table.get(rid)? {
                        // Use parsed original row
                        if needs_remapping {
                            row.remap_references(remapper)?;
                        }
                        emit(rid, &row, &mut buffer)?;
                    }
                }
            }
        });

        // Inserted rows
        for (rid, insert_data) in &inserts {
            // Check if insert was subsequently updated
            let final_data = updates.get(rid).unwrap_or(insert_data);

            let mut resolved_row = (*final_data).clone();
            resolved_row.resolve_placeholders(changes);
            if needs_remapping {
                resolved_row.remap_references(remapper)?;
            }
            emit(*rid, &resolved_row, &mut buffer)?;
        }

        Ok(())
    }

    /// Applies RVA/offset fixups to a row buffer for MethodDef, FieldRVA, and
    /// ManifestResource tables.
    fn apply_rva_fixups(
        buffer: &mut [u8],
        table_id: TableId,
        method_body_rva_map: &HashMap<u32, u32>,
        field_data_rva_map: &HashMap<u32, u32>,
        resource_offset_remap: &HashMap<u32, u32>,
        original_rva_delta: i32,
    ) {
        if table_id == TableId::MethodDef {
            Self::resolve_method_def_rva(buffer, method_body_rva_map, original_rva_delta);
        } else if table_id == TableId::FieldRVA {
            resolve_field_data_rva(buffer, field_data_rva_map);
        } else if table_id == TableId::ManifestResource && !resource_offset_remap.is_empty() {
            // ManifestResource row layout: offset_field (4 bytes) is first.
            // Remap the offset to account for resource data compaction.
            if let Some(rva_slice) = buffer.get(..4) {
                if let Ok(arr) = <[u8; 4]>::try_from(rva_slice) {
                    let old_offset = u32::from_le_bytes(arr);
                    if let Some(&new_offset) = resource_offset_remap.get(&old_offset) {
                        if let Some(out) = buffer.get_mut(..4) {
                            out.copy_from_slice(&new_offset.to_le_bytes());
                        }
                    }
                }
            }
        }
    }

    /// Resolves method RVAs in MethodDef row buffers.
    ///
    /// Updates RVA values to point to new method body locations. This handles:
    /// - Placeholder RVAs (>= 0xF000_0000) from new methods via changes API
    /// - Original RVAs from copied method bodies
    ///
    /// The first 4 bytes of a MethodDef row contain the RVA field.
    ///
    /// # Arguments
    ///
    /// * `buffer` - The raw MethodDef row bytes
    /// * `method_body_rva_map` - Mapping from original/placeholder RVAs to actual RVAs
    /// * `original_rva_delta` - Fallback delta for RVAs not in the map
    fn resolve_method_def_rva(
        buffer: &mut [u8],
        method_body_rva_map: &HashMap<u32, u32>,
        original_rva_delta: i32,
    ) {
        let Some(rva_slice) = buffer.get(..4) else {
            return;
        };
        let Ok(rva_arr) = <[u8; 4]>::try_from(rva_slice) else {
            return;
        };
        let rva = u32::from_le_bytes(rva_arr);

        // RVA 0 means abstract/extern method with no body
        if rva == 0 {
            return;
        }

        // First check the map - this handles both placeholder RVAs and individually
        // copied original method bodies
        let new_rva = if let Some(&mapped_rva) = method_body_rva_map.get(&rva) {
            mapped_rva
        } else if rva < METHOD_BODY_PLACEHOLDER_BASE {
            // Original RVA not in map - apply delta as fallback
            // (used when method bodies region was copied as a whole).
            // If the delta overflows i32, leave the row unchanged rather than
            // writing a corrupt RVA.
            match rva.cast_signed().checked_add(original_rva_delta) {
                Some(v) => v.cast_unsigned(),
                None => return,
            }
        } else {
            // Unmapped placeholder - keep as is (shouldn't happen in valid code)
            rva
        };

        if let Some(out) = buffer.get_mut(..4) {
            out.copy_from_slice(&new_rva.to_le_bytes());
        }
    }

    /// Builds StandAloneSig deduplication mapping.
    ///
    /// Scans the StandAloneSig table and identifies entries with identical blob content.
    /// For each group of duplicates, keeps one canonical entry and maps others to it.
    /// Updates `ctx.standalonesig_skip` with RIDs to skip during table writing,
    /// and adds token remappings to `ctx.tokens` including RID shifts.
    fn build_standalonesig_dedup(&self, ctx: &mut WriteContext, changes: &AssemblyChanges) {
        let view = self.assembly.view();
        let Some(tables) = view.tables() else {
            return;
        };
        let Some(sig_table) = tables.table::<StandAloneSigRaw>() else {
            return;
        };
        let Some(blob_heap) = view.blobs() else {
            return;
        };

        // Get deleted RIDs from changes
        let deleted_rids: HashSet<u32> =
            if let Some(TableModifications::Sparse { deleted_rows, .. }) =
                changes.get_table_modifications(TableId::StandAloneSig)
            {
                deleted_rows.clone()
            } else {
                HashSet::new()
            };

        // Phase 1: Identify duplicates and canonical entries
        // Maps blob content -> canonical RID (first occurrence)
        let mut blob_to_canonical: HashMap<Vec<u8>, u32> = HashMap::new();
        // Maps duplicate RID -> canonical RID
        let mut dup_to_canonical: HashMap<u32, u32> = HashMap::new();

        for sig in sig_table {
            let sig = match sig {
                Ok(row) => row,
                Err(e) => {
                    log::warn!("skipping unreadable metadata row: {e}");
                    continue;
                }
            };
            if deleted_rids.contains(&sig.rid) {
                continue;
            }
            let Ok(blob_bytes) = blob_heap.get(sig.signature as usize) else {
                continue;
            };
            if let Some(&canonical_rid) = blob_to_canonical.get(blob_bytes) {
                dup_to_canonical.insert(sig.rid, canonical_rid);
                ctx.standalonesig_skip.insert(sig.rid);
            } else {
                blob_to_canonical.insert(blob_bytes.to_vec(), sig.rid);
            }
        }

        // Phase 2: Compute output RIDs for original rows
        // Output RID = original RID - (deleted before) - (skipped before)
        let mut output_rid = 0u32;
        let mut rid_to_output: HashMap<u32, u32> = HashMap::new();

        for sig in sig_table {
            let sig = match sig {
                Ok(row) => row,
                Err(e) => {
                    log::warn!("skipping unreadable metadata row: {e}");
                    continue;
                }
            };
            if deleted_rids.contains(&sig.rid) || ctx.standalonesig_skip.contains(&sig.rid) {
                continue;
            }
            output_rid = output_rid.saturating_add(1);
            rid_to_output.insert(sig.rid, output_rid);
        }

        // Phase 2b: Compute output RIDs for inserted rows (appended after originals)
        // Inserted rows are written after all original rows by write_table_data().
        // When original rows are deduplicated/deleted, the inserted rows' output RIDs
        // shift down accordingly.
        if let Some(TableModifications::Sparse { operations, .. }) =
            changes.get_table_modifications(TableId::StandAloneSig)
        {
            let mut inserts: Vec<u32> = operations
                .iter()
                .filter_map(|op| {
                    if let Operation::Insert(rid, _) = &op.operation {
                        Some(*rid)
                    } else {
                        None
                    }
                })
                .collect();
            inserts.sort();

            for rid in inserts {
                output_rid = output_rid.saturating_add(1);
                rid_to_output.insert(rid, output_rid);
            }
        }

        // Phase 3: Build token remapping for original rows
        for sig in sig_table {
            let sig = match sig {
                Ok(row) => row,
                Err(e) => {
                    log::warn!("skipping unreadable metadata row: {e}");
                    continue;
                }
            };
            if deleted_rids.contains(&sig.rid) {
                continue;
            }

            let old_token = Token::from_parts(TableId::StandAloneSig, sig.rid).value();

            if let Some(&canonical_rid) = dup_to_canonical.get(&sig.rid) {
                // Duplicate: map to canonical's output RID
                if let Some(&canon_output) = rid_to_output.get(&canonical_rid) {
                    let new_token = Token::from_parts(TableId::StandAloneSig, canon_output).value();
                    ctx.tokens.insert(old_token, new_token);
                }
            } else if let Some(&new_rid) = rid_to_output.get(&sig.rid) {
                // Non-duplicate: map to shifted output RID if different
                if sig.rid != new_rid {
                    let new_token = Token::from_parts(TableId::StandAloneSig, new_rid).value();
                    ctx.tokens.insert(old_token, new_token);
                }
            }
        }

        // Phase 3b: Build token remapping for inserted rows
        if let Some(TableModifications::Sparse { operations, .. }) =
            changes.get_table_modifications(TableId::StandAloneSig)
        {
            for op in operations {
                if let Operation::Insert(rid, _) = &op.operation {
                    if let Some(&new_rid) = rid_to_output.get(rid) {
                        if *rid != new_rid {
                            let old_token = Token::from_parts(TableId::StandAloneSig, *rid).value();
                            let new_token =
                                Token::from_parts(TableId::StandAloneSig, new_rid).value();
                            ctx.tokens.insert(old_token, new_token);
                        }
                    }
                }
            }
        }
    }

    /// Writes import data (descriptors + ILT + strings) and patches the IAT.
    ///
    /// Uses the imports built during `write_iat()` to generate the import table.
    /// The import table is written after metadata, and the IAT at the start of
    /// .text section is patched with the correct thunk RVAs.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success (including when there are no imports).
    ///
    /// # Errors
    ///
    /// Returns an error if import table generation or writing fails.
    fn write_import_data(ctx: &mut WriteContext) -> Result<()> {
        // Take pending imports built during write_iat()
        let Some(imports) = ctx.pending_imports.take() else {
            // No imports were built - this shouldn't happen for .NET assemblies
            // but handle gracefully
            return Ok(());
        };

        if imports.is_empty() {
            return Ok(());
        }

        ctx.align_to_4();
        let import_table_rva = ctx.current_rva();

        // Generate import table data (descriptors + ILT + strings)
        // FirstThunk fields will point to IAT at ctx.text_section_rva
        let import_table_bytes = imports.build_import_table(
            ctx.is_pe32_plus,
            ctx.text_section_rva, // IAT is at start of .text
            import_table_rva,     // Where we're writing the import table
        )?;

        if import_table_bytes.is_empty() {
            return Ok(());
        }

        // Now generate and patch the IAT content
        // The IAT was written as zeros in write_iat(), now we know the import_table_rva
        let iat_bytes = imports.build_iat_bytes(ctx.is_pe32_plus, import_table_rva)?;

        // Patch the IAT at the start of .text section
        if !iat_bytes.is_empty() {
            ctx.write_at(ctx.iat_offset, &iat_bytes)?;
        }

        // Write import table data
        ctx.import_data_offset = Some(ctx.pos());
        ctx.import_data_rva = Some(import_table_rva);
        ctx.import_data_size = Some(u32::try_from(import_table_bytes.len()).map_err(|_| {
            Error::LayoutFailed(format!(
                "Import data size {} exceeds u32 range",
                import_table_bytes.len()
            ))
        })?);
        ctx.write(&import_table_bytes)?;

        // Write native entry point stub after import table
        Self::write_native_entry_stub(ctx)?;

        Ok(())
    }

    /// Writes the native entry point stub for .NET PE files.
    ///
    /// This writes a small native code stub that performs an indirect jump through
    /// the IAT to _CorExeMain (for EXEs) or _CorDllMain (for DLLs). The Windows
    /// loader jumps to this entry point, which then transfers control to the CLR.
    ///
    /// The stub format is:
    /// - For PE32: `ff 25 xx xx xx xx` (jmp dword ptr [VA]) - 6 bytes
    /// - For PE32+: `ff 25 00 00 00 00` (jmp qword ptr [rip+0]) followed by 8-byte address
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    fn write_native_entry_stub(ctx: &mut WriteContext) -> Result<()> {
        // Align to 4 bytes for entry point
        ctx.align_to_4_with_padding()?;

        // Calculate entry point RVA
        let entry_rva = ctx.current_rva();
        ctx.native_entry_rva = Some(entry_rva);

        // The IAT entry for _CorExeMain/_CorDllMain is at the start of .text section
        // We need the absolute VA (image base + RVA)
        let iat_rva = ctx.text_section_rva;
        let image_base = ctx.image_base;

        if ctx.is_pe32_plus {
            // PE32+ (x64): Use RIP-relative addressing
            // ff 25 00 00 00 00 = jmp qword ptr [rip+0]
            // followed by 8-byte absolute address
            // But for .NET, the stub is simpler: jmp qword ptr [IAT]
            // The offset from RIP (after instruction) to IAT
            let stub_end_rva = entry_rva
                .checked_add(6)
                .ok_or_else(|| Error::LayoutFailed("Entry stub RVA overflow".to_string()))?; // instruction is 6 bytes
            let rel_offset = iat_rva.wrapping_sub(stub_end_rva);
            let stub: [u8; 6] = [
                0xff,
                0x25, // jmp qword ptr [rip+offset]
                (rel_offset & 0xff) as u8,
                ((rel_offset >> 8) & 0xff) as u8,
                ((rel_offset >> 16) & 0xff) as u8,
                ((rel_offset >> 24) & 0xff) as u8,
            ];
            ctx.write(&stub)?;
        } else {
            // PE32 (x86): Use absolute addressing
            // ff 25 xx xx xx xx = jmp dword ptr [VA]
            let iat_va = image_base
                .checked_add(u64::from(iat_rva))
                .ok_or_else(|| Error::LayoutFailed("IAT VA overflow".to_string()))?;
            let stub: [u8; 6] = [
                0xff,
                0x25, // jmp dword ptr [abs]
                (iat_va & 0xff) as u8,
                ((iat_va >> 8) & 0xff) as u8,
                ((iat_va >> 16) & 0xff) as u8,
                ((iat_va >> 24) & 0xff) as u8,
            ];
            ctx.write(&stub)?;
        }

        Ok(())
    }

    /// Writes export data.
    ///
    /// Merges original exports from the assembly with any new exports from changes
    /// and writes the combined export table.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success (including when there are no exports).
    ///
    /// # Errors
    ///
    /// Returns an error if export table serialization or writing fails.
    fn write_export_data(&self, ctx: &mut WriteContext) -> Result<()> {
        let view = self.assembly.view();

        let pe = view.file().pe();
        if let Some(error) = &pe.export_error {
            return Err(Error::LayoutFailed(format!(
                "{error}, so it cannot be written back"
            )));
        }
        let new_exports = self.assembly.changes().native_exports().native();

        // The original directory, with every ordinal and name it holds
        let mut merged = match &pe.export_header {
            Some(header) => NativeExports::from_pe_exports(header, &pe.exports)?,
            None if new_exports.is_empty() => return Ok(()),
            None => NativeExports::new(new_exports.dll_name()),
        };
        // A name the changes set replaces the original's
        if !new_exports.dll_name().is_empty() {
            merged.set_dll_name(new_exports.dll_name())?;
        }

        // Add new exports from changes, but the names already exported
        for func in new_exports.functions() {
            match &func.name {
                Some(name) if merged.has_function(name) => {}
                Some(name) => merged.add_function(name, func.ordinal, func.address)?,
                None => merged.add_function_by_ordinal(func.ordinal, func.address)?,
            }
        }
        for fwd in new_exports.forwarders() {
            match &fwd.name {
                Some(name) if merged.has_function(name) => {}
                name => merged.add_forwarder(
                    name.as_deref().unwrap_or_default(),
                    fwd.ordinal,
                    &fwd.target,
                )?,
            }
        }

        ctx.align_to_4();
        let export_data_offset = ctx.pos();
        let export_data_rva = ctx.current_rva();

        // Serialize export table data
        let export_data_bytes = merged.get_export_table_data_with_base_rva(export_data_rva)?;

        if !export_data_bytes.is_empty() {
            ctx.export_data_offset = Some(export_data_offset);
            ctx.export_data_rva = Some(export_data_rva);
            ctx.export_data_size = Some(u32::try_from(export_data_bytes.len()).map_err(|_| {
                Error::LayoutFailed(format!(
                    "Export data size {} exceeds u32 range",
                    export_data_bytes.len()
                ))
            })?);
            ctx.export_table_bytes = Some(export_data_bytes.clone());
            ctx.write(&export_data_bytes)?;
        }

        Ok(())
    }

    /// Writes embedded PE resources into the .text section if applicable.
    ///
    /// Some assemblies (e.g., WindowsBase.dll) embed Win32 PE resources directly
    /// in the .text section rather than in a separate .rsrc section. The PE data
    /// directory index 2 (ResourceTable) points into .text in these cases.
    ///
    /// Since the writer completely rewrites .text, these resources would be lost
    /// unless explicitly carried over. This method detects the case and copies
    /// the resource data into the new .text section, adjusting internal RVAs
    /// via `relocate_resource_section()`.
    fn write_embedded_pe_resources(&self, ctx: &mut WriteContext) -> Result<()> {
        let view = self.assembly.view();
        let file = view.file();

        // Check if the original PE has a resource directory
        let (res_rva, res_size) = match file.get_data_directory(DataDirectoryType::ResourceTable) {
            Some((rva, size)) if rva != 0 && size != 0 => (rva, size),
            _ => return Ok(()),
        };

        // Check if there's a .rsrc section — if so, resources are handled there
        let has_rsrc_section = file.sections().iter().any(|s| s.name.starts_with(".rsrc"));
        if has_rsrc_section {
            return Ok(());
        }

        // Resources are embedded in .text — read from original file
        let Ok(data) = file.rva_slice(res_rva as usize, res_size as usize) else {
            return Ok(()); // Not in the image, skip
        };

        // Write at aligned position in new .text
        ctx.align_to_4();
        let write_offset = ctx.pos();
        let new_rva = ctx.current_rva();

        // Clone and relocate the resource directory entries if RVA changed
        if res_rva == new_rva {
            ctx.write(&data)?;
        } else {
            let mut rsrc_data = data.to_vec();
            relocate_resource_section(&mut rsrc_data, res_rva, new_rva)?;
            ctx.write(&rsrc_data)?;
        }

        ctx.pe_resource_offset = write_offset;
        ctx.pe_resource_size = res_size;

        Ok(())
    }

    /// Writes all sections except .text (which is handled separately).
    ///
    /// Iterates through sections in order, writing each one at the next aligned
    /// position. Handles special cases:
    /// - `.rsrc`: Relocates resource directory entries if RVA changed
    /// - `.reloc`: Filters out entries pointing to .text, may be removed entirely
    /// - Other sections: Copied as-is from original
    ///
    /// Updates the sections vector with write info for each section.
    fn write_other_sections(&self, ctx: &mut WriteContext) -> Result<()> {
        let view = self.assembly.view();
        let file = view.file();

        // Track current end RVA for calculating next section's RVA
        let mut current_end_rva = u64::from(ctx.text_section_rva)
            .checked_add(ctx.text_section_size)
            .ok_or_else(|| Error::LayoutFailed(".text end RVA overflow".to_string()))?;

        // Get original section info for reloc processing
        let original_text_rva = file
            .sections()
            .iter()
            .find(|s| s.name.starts_with(".text"))
            .map_or(0, |s| s.virtual_address);
        let original_text_size = file
            .sections()
            .iter()
            .find(|s| s.name.starts_with(".text"))
            .map_or(0, |s| s.virtual_size);
        let original_text_end = original_text_rva.saturating_add(original_text_size);

        // Iterate through sections in order
        for section_idx in 0..ctx.sections.len() {
            let section_name = ctx
                .sections
                .get(section_idx)
                .ok_or(out_of_bounds_error!())?
                .name
                .clone();

            // Skip .text - already handled
            if section_name.starts_with(".text") {
                continue;
            }

            // Skip excluded sections
            if self.config.excluded_sections.contains(&section_name) {
                ctx.mark_section_removed(section_idx);
                continue;
            }

            // Find original section data
            let original_section = file.sections().iter().find(|s| s.name == section_name);

            let Some(original_section) = original_section else {
                continue; // Section not found in original, skip
            };

            // Calculate new RVA for this section
            let section_rva =
                u32::try_from(align_to(current_end_rva, u64::from(ctx.section_alignment)))
                    .map_err(|_| {
                        Error::LayoutFailed(format!("Section {section_name} RVA exceeds u32 range"))
                    })?;

            // Handle each section type
            if section_name.starts_with(".rsrc") {
                // Write resource section with relocation
                let data_offset = ctx.pos();
                let data_size = self.write_rsrc_data(ctx, original_section, section_rva)?;
                let raw_size = Self::bytes_written_since(ctx, data_offset)?;

                if data_size > 0 {
                    ctx.update_section(section_idx, data_offset, section_rva, data_size, raw_size);
                    current_end_rva = u64::from(section_rva)
                        .checked_add(u64::from(data_size))
                        .ok_or_else(|| {
                            Error::LayoutFailed("Section end RVA overflow".to_string())
                        })?;
                }
            } else if section_name.starts_with(".reloc") {
                // Write reloc section with filtering
                let data_offset = ctx.pos();
                let result = self.write_reloc_data(
                    ctx,
                    original_section,
                    original_text_rva,
                    original_text_end,
                )?;

                let raw_size = Self::bytes_written_since(ctx, data_offset)?;

                if let Some(data_size) = result {
                    ctx.update_section(section_idx, data_offset, section_rva, data_size, raw_size);
                    current_end_rva = u64::from(section_rva)
                        .checked_add(u64::from(data_size))
                        .ok_or_else(|| {
                            Error::LayoutFailed("Section end RVA overflow".to_string())
                        })?;
                } else {
                    // Reloc section was filtered out entirely
                    ctx.mark_section_removed(section_idx);
                }
            } else {
                // Copy other sections as-is
                let data_offset = ctx.pos();
                // `data_size` is the section's virtual extent; `raw_size` is what actually
                // reached the file. For a copied section these differ whenever the input's
                // `VirtualSize` and `SizeOfRawData` differ — uninitialised data in one
                // direction, file-alignment padding in the other — and `SizeOfRawData` must
                // describe the bytes, not the extent.
                let data_size = self.write_generic_section(ctx, original_section)?;
                let raw_size = Self::bytes_written_since(ctx, data_offset)?;

                if data_size > 0 {
                    ctx.update_section(section_idx, data_offset, section_rva, data_size, raw_size);
                    current_end_rva = u64::from(section_rva)
                        .checked_add(u64::from(data_size))
                        .ok_or_else(|| {
                            Error::LayoutFailed("Section end RVA overflow".to_string())
                        })?;
                }
            }

            // Align to file alignment. This padding is required because PE spec
            // mandates SizeOfRawData be a multiple of FileAlignment, and the file
            // must contain those bytes.
            ctx.align_to_file()?;
        }

        Ok(())
    }

    /// Writes resource section data with relocation handling.
    ///
    /// Returns the size of data written, or 0 if no data.
    fn write_rsrc_data(
        &self,
        ctx: &mut WriteContext,
        section: &SectionTable,
        new_rva: u32,
    ) -> Result<u32> {
        let view = self.assembly.view();
        let file = view.file();
        let Some((data, extent)) = section_contents(file, section) else {
            return Ok(0);
        };

        // Relocate if RVA changed
        if section.virtual_address == new_rva {
            ctx.write(data)?;
        } else {
            let mut rsrc_data = data.to_vec();
            relocate_resource_section(&mut rsrc_data, section.virtual_address, new_rva)?;
            ctx.write(&rsrc_data)?;
        }

        Ok(extent)
    }

    /// Writes reloc section data with proper CoreCLR compliance.
    ///
    /// Handles relocations based on assembly type:
    /// - x64 IL-only EXE: Remove .reloc, set RELOCS_STRIPPED flag
    /// - x86 IL-only EXE: Generate entry stub relocation
    /// - DLLs: Always generate relocations (CoreCLR requirement)
    /// - Mixed-mode: Filter existing relocations
    ///
    /// Returns Some(size) if data was written, None if section should be removed.
    fn write_reloc_data(
        &self,
        ctx: &mut WriteContext,
        section: &SectionTable,
        original_text_rva: u32,
        original_text_end: u32,
    ) -> Result<Option<u32>> {
        let view = self.assembly.view();
        let file = view.file();

        // Get original reloc data if present
        let existing_data = section_contents(file, section).map(|(data, _)| data);

        // Build relocation configuration
        let config = RelocationConfig {
            is_dll: self.is_dll(),
            is_pe32_plus: ctx.is_pe32_plus,
            is_il_only: self.is_il_only(),
            entry_stub_rva: ctx.native_entry_rva,
        };

        // Generate relocations using the new module
        let result = generate_relocations(
            &config,
            existing_data,
            (original_text_rva, original_text_end),
        );

        // Store the strip flag for later fixup
        ctx.relocs_stripped = result.strip_relocations;

        if result.data.is_empty() {
            return Ok(None);
        }

        let size = u32::try_from(result.data.len()).unwrap_or(0);
        ctx.write(&result.data)?;

        Ok(Some(size))
    }

    /// Copies the debug directory, and the data each of its entries points at, into `.text`,
    /// pointing the entries at the copies (the PE format's `IMAGE_DEBUG_DIRECTORY`, 28 bytes
    /// an entry).
    ///
    /// # Errors
    ///
    /// When the directory or an entry's data lies outside the input.
    fn write_debug_data(&self, ctx: &mut WriteContext) -> Result<()> {
        const ENTRY: usize = 28;
        let Some((rva, size)) = ctx.original_debug_dir else {
            return Ok(());
        };
        let file = self.assembly.view().file();
        let directory = file.rva_slice(rva as usize, size as usize)?.into_owned();
        let mut copied = directory.clone();
        let field = |entry: &[u8], at: usize| -> u32 {
            entry
                .get(at..at.saturating_add(4))
                .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                .map_or(0, u32::from_le_bytes)
        };
        for (index, entry) in directory.as_chunks::<ENTRY>().0.iter().enumerate() {
            let (data_size, data_rva, data_pointer) =
                (field(entry, 16), field(entry, 20), field(entry, 24));
            if data_size == 0 {
                continue;
            }
            // The file pointer is where the bytes are; an entry whose data is not mapped
            // has no RVA
            let data = if data_pointer != 0 {
                file.data_slice(data_pointer as usize, data_size as usize)?
                    .to_vec()
            } else {
                file.rva_slice(data_rva as usize, data_size as usize)?
                    .into_owned()
            };
            ctx.align_to_4_with_padding()?;
            let (new_rva, new_pointer) = (ctx.current_rva(), ctx.pos());
            ctx.write(&data)?;
            let base = index.saturating_mul(ENTRY);
            if data_rva != 0 {
                if let Some(slot) = copied.get_mut(base.saturating_add(20)..base.saturating_add(24))
                {
                    slot.copy_from_slice(&new_rva.to_le_bytes());
                }
            }
            if data_pointer != 0 {
                let pointer = u32::try_from(new_pointer).map_err(|_| {
                    Error::LayoutFailed("Debug data offset exceeds u32 range".to_string())
                })?;
                if let Some(slot) = copied.get_mut(base.saturating_add(24)..base.saturating_add(28))
                {
                    slot.copy_from_slice(&pointer.to_le_bytes());
                }
            }
        }
        ctx.align_to_4_with_padding()?;
        ctx.debug_dir = Some((ctx.current_rva(), size));
        ctx.write(&copied)?;
        Ok(())
    }

    /// Returns how many bytes have been written since `start`.
    ///
    /// Measured from the output position rather than trusted from a return value, so
    /// `SizeOfRawData` cannot drift from what the section writer actually emitted.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::LayoutFailed`] if the position moved backwards or the delta
    /// exceeds `u32`.
    fn bytes_written_since(ctx: &WriteContext, start: u64) -> Result<u32> {
        let written = ctx.pos().checked_sub(start).ok_or_else(|| {
            Error::LayoutFailed("Section write position moved backwards".to_string())
        })?;
        u32::try_from(written)
            .map_err(|_| Error::LayoutFailed("Section written size exceeds u32 range".to_string()))
    }

    /// Writes a generic section by copying its contents as-is.
    ///
    /// Returns the section's size in the image, or 0 if it has no data.
    fn write_generic_section(&self, ctx: &mut WriteContext, section: &SectionTable) -> Result<u32> {
        let view = self.assembly.view();
        let Some((data, extent)) = section_contents(view.file(), section) else {
            return Ok(0);
        };
        ctx.write(data)?;
        Ok(extent)
    }
}

/// Every `#US` offset an `ldstr` of the assembly's bodies names: the original bodies and the
/// ones a change stores. A body that does not decode names none it can be held to.
fn collect_referenced_userstring_offsets(assembly: &CilAssembly) -> HashSet<u32> {
    let mut offsets = HashSet::new();
    let mut scan = |body: &[u8]| {
        let Ok(header) = MethodBody::from(body) else {
            return;
        };
        let Some(code) = header
            .size_header
            .checked_add(header.size_code)
            .and_then(|end| body.get(header.size_header..end))
        else {
            return;
        };
        let Ok(instructions) = decode_stream(&mut Parser::new(code), 0) else {
            return;
        };
        for instruction in instructions {
            if let Operand::Token(token) = instruction.operand {
                if token.table() == 0x70 {
                    offsets.insert(token.row());
                }
            }
        }
    };
    let view = assembly.view();
    let file = view.file();
    if let Some(methods) = view.tables().and_then(|t| t.table::<MethodDefRaw>()) {
        for row in methods.iter().flatten() {
            let code_type = MethodImplCodeType::from_impl_flags(row.impl_flags);
            if row.rva == 0
                || row.rva >= METHOD_BODY_PLACEHOLDER_BASE
                || code_type.contains(MethodImplCodeType::NATIVE)
                || code_type.contains(MethodImplCodeType::RUNTIME)
            {
                continue;
            }
            if let Ok(body) = file.section_bounded(row.rva as usize) {
                scan(body);
            }
        }
    }
    for (_, body) in assembly.changes().method_bodies() {
        scan(body);
    }
    offsets
}

/// A section's contents as the loader maps them ([`SectionMap::contents`]): the raw data the
/// file holds within its size in the image, and that size. `None` when it holds no data.
///
/// [`SectionMap::contents`]: crate::file::sectionmap::SectionMap::contents
fn section_contents<'a>(file: &'a File, section: &SectionTable) -> Option<(&'a [u8], u32)> {
    let (extent, data) = file.section_map().contents(file.data(), section);
    (!data.is_empty()).then_some((data, extent))
}

#[cfg(test)]
mod tests {

    use tempfile::NamedTempFile;

    use crate::{
        cilassembly::{writer::generator::PeGenerator, CilAssembly},
        metadata::{
            signatures::TypeSignature,
            tables::{
                CodedIndex, CodedIndexType, CustomAttributeBuilder, CustomAttributeRaw,
                GenericParamBuilder, GenericParamConstraintRaw, GenericParamRaw, TableId,
            },
            token::Token,
        },
        testkit::fixture,
        CilAssemblyView, CilObject, MethodBuilder,
    };

    const SAMPLE: &str = "crafted_2.exe";

    /// An attribute added to a method goes where the CustomAttribute table's
    /// sort order puts it, not at the end, and the method finds it. Appended
    /// under a header that still called the table sorted, the runtime's binary
    /// search would miss it.
    #[test]
    fn an_added_attribute_is_written_where_its_table_sorts_it() {
        let target = Token::new(0x0600_0001);
        let before = CilObject::from_path(fixture(SAMPLE))
            .and_then(|object| object.method(&target))
            .expect("the method loads")
            .custom_attributes
            .count();

        let view = CilAssemblyView::from_path(fixture(SAMPLE)).expect("the sample loads");
        // Copy an existing attribute's constructor and blob, so the added one
        // decodes like any other.
        let (constructor, value) = {
            let row = view
                .tables()
                .and_then(|tables| tables.table::<CustomAttributeRaw>())
                .and_then(|table| table.get(1).ok().flatten())
                .expect("the sample has attributes");
            let value = view
                .blobs()
                .and_then(|blobs| blobs.get(row.value as usize).ok())
                .expect("the attribute's blob")
                .to_vec();
            (row.constructor, value)
        };
        let mut assembly = CilAssembly::new(view);
        CustomAttributeBuilder::new()
            .parent(CodedIndex::new(
                TableId::MethodDef,
                target.row(),
                CodedIndexType::HasCustomAttribute,
            ))
            .constructor(constructor)
            .value(&value)
            .build(&mut assembly)
            .expect("the attribute is added");

        let written = assembly
            .into_cilobject()
            .expect("the output loads, sort order included");
        let method = written.method(&target).expect("the method survives");
        assert_eq!(method.custom_attributes.count(), before + 1);

        let parents: Vec<Token> = written
            .tables()
            .and_then(|tables| tables.table::<CustomAttributeRaw>())
            .expect("the attribute table")
            .iter()
            .flatten()
            .map(|row| row.parent.token)
            .collect();
        let at = parents.iter().position(|parent| *parent == target);
        assert!(
            at.is_some_and(|at| at + 1 < parents.len()),
            "the attribute sorts ahead of the rest, not after them: {at:?} of {}",
            parents.len()
        );
    }

    /// Each generic parameter constraint as the owner of its parameter, the
    /// parameter's name, and the constraint.
    fn constraints_of(object: &CilObject) -> Vec<(Token, String, Token)> {
        let tables = object.tables().expect("tables");
        let strings = object.strings().expect("strings");
        let params = tables
            .table::<GenericParamRaw>()
            .expect("generic parameters");
        let mut described: Vec<(Token, String, Token)> = tables
            .table::<GenericParamConstraintRaw>()
            .expect("constraints")
            .iter()
            .flatten()
            .map(|constraint| {
                let param = params
                    .get(constraint.owner)
                    .ok()
                    .flatten()
                    .expect("the constraint's parameter");
                let name = strings
                    .get(param.name as usize)
                    .expect("the name")
                    .to_string();
                (param.owner.token, name, constraint.constraint.token)
            })
            .collect();
        described.sort();
        described
    }

    /// Adding a generic parameter whose owner sorts ahead of every other
    /// moves each existing parameter down a row, and every constraint follows
    /// its own parameter there.
    #[test]
    fn constraints_follow_their_parameters_when_the_parameters_are_sorted() {
        let original = CilObject::from_path(fixture(SAMPLE)).expect("the sample loads");
        let expected = constraints_of(&original);
        assert!(
            !expected.is_empty(),
            "the sample constrains generic parameters"
        );

        // The first type that has no parameters of its own: its owner key is
        // below every existing parameter's.
        let owners: Vec<Token> = original
            .tables()
            .and_then(|tables| tables.table::<GenericParamRaw>())
            .expect("generic parameters")
            .iter()
            .flatten()
            .map(|param| param.owner.token)
            .collect();
        let owner = (2..)
            .map(|rid| Token::from_parts(TableId::TypeDef, rid))
            .find(|token| !owners.contains(token))
            .expect("a type without parameters");
        assert!(
            owners
                .iter()
                .any(|existing| existing.value() > owner.value()),
            "the new parameter sorts ahead of an existing one"
        );

        let view = CilAssemblyView::from_path(fixture(SAMPLE)).expect("the sample loads");
        let mut assembly = CilAssembly::new(view);
        GenericParamBuilder::new()
            .name("TAdded")
            .number(0)
            .owner(CodedIndex::new(
                TableId::TypeDef,
                owner.row(),
                CodedIndexType::TypeOrMethodDef,
            ))
            .build(&mut assembly)
            .expect("the parameter is added");

        let written = assembly
            .into_cilobject()
            .expect("the output loads, sort order included");
        assert_eq!(constraints_of(&written), expected);
    }

    #[test]
    fn test_pe_generator_basic() {
        let view = CilAssemblyView::from_path(fixture("crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let generator = PeGenerator::new(&assembly);
        let result = generator.to_file(temp_file.path());

        assert!(
            result.is_ok(),
            "PE generation should succeed: {:?}",
            result.err()
        );

        // Verify the generated file can be loaded
        let reloaded = CilAssemblyView::from_path(temp_file.path());
        assert!(
            reloaded.is_ok(),
            "Generated PE should be loadable: {:?}",
            reloaded.err()
        );
    }

    #[test]
    fn test_pe_generator_with_modifications() {
        let view = CilAssemblyView::from_path(fixture("crafted_2.exe"))
            .expect("Failed to load test assembly");

        let original_method_count = view
            .tables()
            .map(|t| t.table_row_count(TableId::MethodDef))
            .unwrap_or(0);

        let mut assembly = CilAssembly::new(view);

        let _method_token = MethodBuilder::new("TestGeneratorMethod")
            .public()
            .static_method()
            .parameter("a", TypeSignature::I4)
            .parameter("b", TypeSignature::I4)
            .returns(TypeSignature::I4)
            .implementation(|body| {
                body.implementation(|asm| {
                    asm.ldarg_0()?.ldarg_1()?.add()?.ret()?;
                    Ok(())
                })
            })
            .build(&mut assembly)
            .expect("Failed to build method");

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        assembly.to_file(temp_file.path()).expect("Write failed");

        let reloaded =
            CilAssemblyView::from_path(temp_file.path()).expect("Failed to reload generated PE");

        let new_method_count = reloaded
            .tables()
            .map(|t| t.table_row_count(TableId::MethodDef))
            .unwrap_or(0);

        assert!(
            new_method_count > original_method_count,
            "Method count should have increased: {} -> {}",
            original_method_count,
            new_method_count
        );
    }

    #[test]
    fn test_pe_generator_to_memory() {
        let view = CilAssemblyView::from_path(fixture("crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let generator = PeGenerator::new(&assembly);
        let result = generator.to_memory();

        assert!(
            result.is_ok(),
            "In-memory PE generation should succeed: {:?}",
            result.err()
        );

        let pe_bytes = result.unwrap();

        // Verify basic PE structure
        assert!(
            pe_bytes.len() > 512,
            "Generated PE should be larger than 512 bytes"
        );
        assert_eq!(&pe_bytes[0..2], b"MZ", "PE should start with MZ signature");

        // Get e_lfanew offset (at 0x3C)
        let e_lfanew = u32::from_le_bytes([
            pe_bytes[0x3C],
            pe_bytes[0x3D],
            pe_bytes[0x3E],
            pe_bytes[0x3F],
        ]) as usize;

        // Verify PE signature at e_lfanew
        assert_eq!(
            &pe_bytes[e_lfanew..e_lfanew + 4],
            b"PE\0\0",
            "PE signature should be at e_lfanew offset"
        );
    }

    #[test]
    fn test_pe_generator_to_memory_can_reload() {
        let view = CilAssemblyView::from_path(fixture("crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let generator = PeGenerator::new(&assembly);
        let pe_bytes = generator.to_memory().expect("Generation should succeed");

        // Verify the in-memory bytes can be loaded as an assembly
        let reloaded = CilAssemblyView::from_mem(pe_bytes);
        assert!(
            reloaded.is_ok(),
            "Generated PE bytes should be loadable: {:?}",
            reloaded.err()
        );
    }

    #[test]
    fn test_pe_generator_to_memory_with_modifications() {
        let view = CilAssemblyView::from_path(fixture("crafted_2.exe"))
            .expect("Failed to load test assembly");

        let original_method_count = view
            .tables()
            .map(|t| t.table_row_count(TableId::MethodDef))
            .unwrap_or(0);

        let mut assembly = CilAssembly::new(view);

        let _method_token = MethodBuilder::new("TestMemoryMethod")
            .public()
            .static_method()
            .parameter("x", TypeSignature::I4)
            .returns(TypeSignature::I4)
            .implementation(|body| {
                body.implementation(|asm| {
                    asm.ldarg_0()?.ret()?;
                    Ok(())
                })
            })
            .build(&mut assembly)
            .expect("Failed to build method");

        // Generate to memory instead of file
        let generator = PeGenerator::new(&assembly);
        let pe_bytes = generator
            .to_memory()
            .expect("In-memory generation should succeed");

        // Load from bytes
        let reloaded = CilAssemblyView::from_mem(pe_bytes).expect("Failed to reload from bytes");

        let new_method_count = reloaded
            .tables()
            .map(|t| t.table_row_count(TableId::MethodDef))
            .unwrap_or(0);

        assert!(
            new_method_count > original_method_count,
            "Method count should have increased: {} -> {}",
            original_method_count,
            new_method_count
        );
    }

    #[test]
    fn test_pe_generator_file_and_memory_produce_same_result() {
        let view = CilAssemblyView::from_path(fixture("crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        // Generate to file
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let generator = PeGenerator::new(&assembly);
        generator
            .to_file(temp_file.path())
            .expect("File generation failed");

        // Read the file back
        let file_bytes = std::fs::read(temp_file.path()).expect("Failed to read generated file");

        // Generate to memory
        let memory_bytes = generator.to_memory().expect("Memory generation failed");

        // Compare the two
        assert_eq!(
            file_bytes.len(),
            memory_bytes.len(),
            "File and memory generation should produce same size: file={}, memory={}",
            file_bytes.len(),
            memory_bytes.len()
        );
        assert_eq!(
            file_bytes, memory_bytes,
            "File and memory generation should produce identical bytes"
        );
    }
}

#[cfg(test)]
mod examples {
    use super::*;
    use crate::{testkit::fixture, CilAssemblyView, Result};

    /// An assembly written to memory loads back with the same methods.
    #[test]
    fn to_memory_example() -> Result<()> {
        let assembly = CilAssembly::from_path(fixture("crafted_2.exe"))?;
        // ... modify assembly ...

        let pe_bytes = PeGenerator::new(&assembly).to_memory()?;

        let original = assembly
            .view()
            .tables()
            .expect("tables")
            .table_row_count(TableId::MethodDef);
        let written = CilAssemblyView::from_mem(pe_bytes)?;
        assert_eq!(
            written
                .tables()
                .expect("tables")
                .table_row_count(TableId::MethodDef),
            original
        );
        Ok(())
    }
}

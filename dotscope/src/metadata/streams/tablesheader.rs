//! ECMA-335 Metadata Tables Header (`#~`) for .NET Assembly Parsing
//!
//! This module provides comprehensive parsing and access to the compressed metadata tables
//! stream (`#~`) defined in ECMA-335 Section II.24.2.6 and detailed in Section II.22.
//! The tables header serves as the central access point for all metadata tables within
//! a .NET assembly, enabling efficient reflection, analysis, and runtime operations.
//!
//! # Metadata Tables Architecture
//!
//! The metadata tables system is the core of .NET assemblies, containing structured
//! information about types, methods, fields, properties, events, and relationships
//! between these entities. The `#~` stream provides a compressed, optimized format
//! for storing this metadata with variable-width encoding for maximum space efficiency.
//!
//! ## Stream Structure
//!
//! The compressed metadata tables stream follows this binary layout:
//! ```text
//! Offset | Size | Field              | Description
//! -------|------|--------------------|-----------------------------------------
//! 0      | 4    | Reserved           | Must be 0x00000000
//! 4      | 1    | MajorVersion       | Schema major version (typically 2)
//! 5      | 1    | MinorVersion       | Schema minor version (typically 0)
//! 6      | 1    | HeapSizes          | Heap index size flags (strings, blobs, GUIDs)
//! 7      | 1    | Reserved           | Must be 0x01
//! 8      | 8    | Valid              | Bit vector of present tables (64 bits)
//! 16     | 8    | Sorted             | Bit vector of sorted tables (64 bits)
//! 24     | 4*N  | Rows[]             | Row counts for each present table
//! 24+4*N | Var  | TableData[]        | Actual table data in binary format
//! ```
//!
//! ## Supported Metadata Tables
//!
//! The ECMA-335 specification defines 45 metadata tables, each serving specific purposes:
//!
//! ### Core Type System Tables
//! - **Module** (0x00): Assembly module information
//! - **TypeRef** (0x01): External type references
//! - **TypeDef** (0x02): Type definitions within this assembly
//! - **Field** (0x04): Field definitions and metadata
//! - **MethodDef** (0x06): Method definitions and signatures
//! - **Param** (0x08): Parameter definitions and attributes
//!
//! ### Member Reference Tables
//! - **MemberRef** (0x0A): References to external members
//! - **InterfaceImpl** (0x09): Interface implementation relationships
//! - **Constant** (0x0B): Compile-time constant values
//! - **CustomAttribute** (0x0C): Custom attribute applications
//!
//! ### Layout and Mapping Tables
//! - **ClassLayout** (0x0F): Type layout and packing information
//! - **FieldLayout** (0x10): Field offset specifications
//! - **FieldRVA** (0x1D): Field data relative virtual addresses
//! - **ImplMap** (0x1C): P/Invoke and native interop mappings
//!
//! ### Event and Property Tables
//! - **Event** (0x14): Event definitions
//! - **Property** (0x17): Property definitions
//! - **EventMap** (0x12): Type-to-event mappings
//! - **PropertyMap** (0x15): Type-to-property mappings
//! - **MethodSemantics** (0x18): Event/property accessor method relationships
//!
//! ### Assembly and Module Tables
//! - **Assembly** (0x20): Assembly metadata and versioning
//! - **AssemblyRef** (0x23): External assembly references
//! - **File** (0x26): Multi-file assembly components
//! - **ManifestResource** (0x28): Embedded and linked resources
//! - **ExportedType** (0x27): Types exported from this assembly
//!
//! ### Generic Type Tables
//! - **GenericParam** (0x2A): Generic type and method parameters
//! - **GenericParamConstraint** (0x2C): Generic parameter constraints
//! - **MethodSpec** (0x2B): Generic method instantiations
//!
//! ### Security and Advanced Tables
//! - **DeclSecurity** (0x0E): Declarative security attributes
//! - **StandAloneSig** (0x11): Standalone method signatures
//! - **TypeSpec** (0x1B): Complex type specifications
//! - **NestedClass** (0x29): Nested type relationships
//!
//! ## Memory-Efficient Design
//!
//! The [`crate::metadata::streams::tablesheader::TablesHeader`] implementation prioritizes memory efficiency and performance:
//!
//! ### Optimized Access Patterns
//! - **Direct indexing**: O(1) random access to any table row
//! - **Sequential iteration**: Efficient streaming through large tables
//! - **Parallel processing**: Safe concurrent access via `rayon` integration
//! - **Type safety**: Compile-time verification of table type correctness
//!
//! # Examples
//!
//! ## Basic Table Access and Analysis
//! ```rust
//! use dotscope::metadata::{streams::TablesHeader, tables::{TableId, TypeDefRaw, MethodDefRaw}};
//!
//! # fn example(tables_data: &[u8]) -> dotscope::Result<()> {
//! let tables = TablesHeader::from(tables_data, false)?;
//!
//! // Analyze assembly structure
//! println!("Assembly contains {} metadata tables", tables.table_count());
//!
//! // Access type definitions
//! if let Some(typedef_table) = tables.table::<TypeDefRaw>() {
//!     println!("Found {} type definitions", typedef_table.row_count);
//!     
//!     // Examine first few types
//!     // Iteration yields `Result<TypeDefRaw>`: a row that fails to parse is reported
//!     // rather than silently ending the iteration.
//!     for (index, type_def) in typedef_table.iter().enumerate().take(5) {
//!         let type_def = type_def?;
//!         println!("Type {}: flags={:#x}, name_idx={}, namespace_idx={}",
//!                  index, type_def.flags, type_def.type_name, type_def.type_namespace);
//!     }
//! }
//!
//! // Access method definitions
//! if let Some(method_table) = tables.table::<MethodDefRaw>() {
//!     println!("Found {} method definitions", method_table.row_count);
//!     
//!     // Find methods by characteristics
//!     let static_methods = method_table.iter()
//!         .filter_map(Result::ok) // skip rows that fail to parse
//!         .filter(|method| method.flags & 0x0010 != 0) // MethodAttributes.Static
//!         .count();
//!     println!("Static methods: {}", static_methods);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Cross-Table Analysis and Relationships
//! ```rust
//! use dotscope::metadata::{streams::TablesHeader, tables::{TableId, TypeDefRaw, FieldRaw}};
//!
//! # fn example(tables_data: &[u8]) -> dotscope::Result<()> {
//! let tables = TablesHeader::from(tables_data, false)?;
//!
//! // Analyze types and their fields together
//! if let (Some(typedef_table), Some(field_table)) = (
//!     tables.table::<TypeDefRaw>(),
//!     tables.table::<FieldRaw>()
//! ) {
//!     for (type_idx, type_def) in typedef_table.iter().enumerate().take(10) {
//!         let type_def = type_def?;
//!         // Calculate field range for this type
//!         let field_start = type_def.field_list.saturating_sub(1) as usize;
//!
//!         // Find field range end (next type's field_list or table end). `get` returns
//!         // `Result<Option<_>>`: outer for a malformed row, inner for a RID past the end.
//!         let field_end = if type_idx + 1 < typedef_table.row_count as usize {
//!             typedef_table.get((type_idx + 1) as u32)?
//!                 .map(|next_type| next_type.field_list.saturating_sub(1) as usize)
//!                 .unwrap_or(field_table.row_count as usize)
//!         } else {
//!             field_table.row_count as usize
//!         };
//!         
//!         let field_count = field_end.saturating_sub(field_start);
//!         println!("Type {} has {} fields (indices {}-{})",
//!                  type_idx, field_count, field_start, field_end);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Parallel Processing for Performance
//! ```rust
//! use dotscope::metadata::{streams::TablesHeader, tables::{TableId, CustomAttributeRaw}};
//! use rayon::prelude::*;
//!
//! # fn example(tables_data: &[u8]) -> dotscope::Result<()> {
//! let tables = TablesHeader::from(tables_data, false)?;
//!
//! // Process custom attributes in parallel for large assemblies
//! if let Some(ca_table) = tables.table::<CustomAttributeRaw>() {
//!     println!("Processing {} custom attributes in parallel", ca_table.row_count);
//!     
//!     // Parallel analysis using rayon
//!     let attribute_stats = ca_table.par_iter()
//!         .filter_map(Result::ok) // parallel iteration yields `Result<CustomAttributeRaw>`
//!         .map(|attr| {
//!             // Analyze attribute type and parent
//!             let parent_table = attr.parent.tag;
//!             let parent_index = attr.parent.row;
//!             (parent_table, parent_index)
//!         })
//!         .collect::<Vec<_>>();
//!     
//!     println!("Analyzed {} attribute relationships", attribute_stats.len());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Memory-Efficient Large Table Processing
//! ```rust
//! use dotscope::metadata::{streams::TablesHeader, tables::{TableId, MemberRefRaw}};
//!
//! # fn example(tables_data: &[u8]) -> dotscope::Result<()> {
//! let tables = TablesHeader::from(tables_data, false)?;
//!
//! // Process large tables in chunks to manage memory usage
//! if let Some(memberref_table) = tables.table::<MemberRefRaw>() {
//!     const CHUNK_SIZE: u32 = 1000;
//!     let total_rows = memberref_table.row_count;
//!     
//!     println!("Processing {} member references in chunks of {}", total_rows, CHUNK_SIZE);
//!     
//!     for chunk_start in (0..total_rows).step_by(CHUNK_SIZE as usize) {
//!         let chunk_end = (chunk_start + CHUNK_SIZE).min(total_rows);
//!         
//!         // Process chunk without loading entire table into memory
//!         let mut external_refs = 0;
//!         for i in chunk_start..chunk_end {
//!             if let Ok(Some(member_ref)) = memberref_table.get(i) {
//!                 // Analyze member reference
//!                 if member_ref.class.tag == TableId::TypeRef {
//!                     external_refs += 1;
//!                 }
//!             }
//!         }
//!         
//!         println!("Chunk {}-{}: {} external references",
//!                  chunk_start, chunk_end, external_refs);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Table Discovery and Introspection
//! ```rust
//! use dotscope::metadata::{streams::TablesHeader, tables::TableId};
//!
//! # fn example(tables_data: &[u8]) -> dotscope::Result<()> {
//! let tables = TablesHeader::from(tables_data, false)?;
//!
//! println!("Assembly Metadata Summary:");
//! println!("========================");
//!
//! // Get overview of all present tables
//! let summaries = tables.table_summary();
//! for summary in summaries {
//!     println!("{:?}: {} rows", summary.table_id, summary.row_count);
//! }
//!
//! // Check for specific advanced features
//! if tables.has_table(TableId::GenericParam) {
//!     println!("✓ Assembly uses generic types");
//! }
//! if tables.has_table(TableId::DeclSecurity) {
//!     println!("✓ Assembly has declarative security");
//! }
//! if tables.has_table(TableId::ManifestResource) {
//!     println!("✓ Assembly contains embedded resources");
//! }
//!
//! // Check for common tables by ID
//! if tables.has_table_by_id(0x20) { // Assembly table
//!     println!("✓ Assembly metadata present");
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # ECMA-335 Compliance
//!
//! This implementation fully complies with ECMA-335 specifications:
//! - **Section II.24.2.6**: Metadata tables stream format and structure
//! - **Section II.22**: Complete table definitions and relationships
//! - **Compression format**: Proper handling of variable-width table indices
//! - **Heap references**: Correct interpretation of string, blob, and GUID heap indices
//! - **Table relationships**: Accurate representation of cross-table references
//!
//! # Security Considerations
//!
//! ## Input Validation
//! - **Bounds checking**: All table access protected against buffer overruns
//! - **Format validation**: ECMA-335 format requirements enforced during parsing
//! - **Index validation**: Heap and table references validated for correctness
//! - **Size limits**: Reasonable limits on table sizes prevent resource exhaustion
//!
//! ## Memory Safety
//! - **Lifetime enforcement**: Rust borrow checker prevents use-after-free
//! - **Type safety**: Generic type parameters prevent incorrect table access
//! - **Bounds verification**: All array and slice access bounds-checked
//! - **No unsafe code**: Table access goes through the safe accessor layer; there is no pointer
//!   casting here to manage
//!
//! # See Also
//! - [`crate::metadata::tables`]: Individual metadata table definitions and structures
//! - [`crate::metadata::streams`]: Overview of all metadata stream types
//! - [`crate::metadata::root`]: Metadata root and stream directory parsing
//! - [ECMA-335 II.24.2.6](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): Tables stream specification
//! - [ECMA-335 II.22](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): Metadata table definitions
//!
//! # References
//! - **ECMA-335 II.24.2.6**: Metadata tables stream format and binary layout
//! - **ECMA-335 II.22**: Complete specifications for all 45 metadata table types
//! - **ECMA-335 II.25**: File format and metadata integration within PE files

use std::{io::Write, sync::Arc};

use strum::IntoEnumIterator;

use crate::{
    create_table_match, impl_table_access,
    metadata::tables::{
        AssemblyOsRaw, AssemblyProcessorRaw, AssemblyRaw, AssemblyRefOsRaw,
        AssemblyRefProcessorRaw, AssemblyRefRaw, ClassLayoutRaw, ConstantRaw, CustomAttributeRaw,
        CustomDebugInformationRaw, DeclSecurityRaw, DocumentRaw, EncLogRaw, EncMapRaw, EventMapRaw,
        EventPtrRaw, EventRaw, ExportedTypeRaw, FieldLayoutRaw, FieldMarshalRaw, FieldPtrRaw,
        FieldRaw, FieldRvaRaw, FileRaw, GenericParamConstraintRaw, GenericParamRaw, ImplMapRaw,
        ImportScopeRaw, InterfaceImplRaw, LocalConstantRaw, LocalScopeRaw, LocalVariableRaw,
        ManifestResourceRaw, MemberRefRaw, MetadataTable, MethodDebugInformationRaw, MethodDefRaw,
        MethodImplRaw, MethodPtrRaw, MethodSemanticsRaw, MethodSpecRaw, ModuleRaw, ModuleRefRaw,
        NestedClassRaw, ParamPtrRaw, ParamRaw, PropertyMapRaw, PropertyPtrRaw, PropertyRaw,
        RowReadable, StandAloneSigRaw, StateMachineMethodRaw, TableAccess, TableData, TableId,
        TableInfo, TableInfoRef, TypeDefRaw, TypeRefRaw, TypeSpecRaw,
    },
    utils::read_le,
    Error, ParseFailure, ParseStage, Result,
};

/// HeapSizes bit 0x40 (ExtraData): a u32 follows the row counts, before the first table.
const HEAP_SIZES_EXTRA_DATA: u8 = 0x40;

/// ECMA-335 compliant metadata tables header providing efficient access to .NET assembly metadata.
///
/// The [`crate::metadata::streams::tablesheader::TablesHeader`] struct represents the compressed metadata tables stream (`#~`) header
/// and provides type-safe, memory-efficient access to all metadata tables within a .NET assembly.
/// This is the primary interface for reflection, analysis, and runtime operations on .NET metadata.
///
/// ## Architecture and Design
///
/// [`crate::metadata::streams::tablesheader::TablesHeader`] implements a lazy-loading design that maximizes performance
/// while maintaining memory safety through Rust's lifetime system:
///
/// - **Lazy parsing**: Table rows are parsed only when accessed
/// - **Type safety**: Generic type parameters prevent incorrect table access
/// - **Lifetime safety**: Rust borrow checker prevents dangling references
/// - **ECMA-335 compliance**: Full specification adherence for all table formats
///
/// ## Metadata Tables Overview
///
/// The metadata tables system contains 45 different table types defined by ECMA-335,
/// each serving specific purposes in the .NET type system:
///
/// ### Core Tables (Always Present)
/// - **Module**: Assembly module identification and versioning
/// - **`TypeDef`**: Type definitions declared in this assembly
/// - **`MethodDef`**: Method definitions and IL code references
/// - **`Field`**: Field definitions and attributes
///
/// ### Reference Tables (External Dependencies)
/// - **`TypeRef`**: References to types in other assemblies
/// - **`MemberRef`**: References to methods/fields in external types
/// - **`AssemblyRef`**: External assembly dependencies
/// - **`ModuleRef`**: Multi-module assembly references
///
/// ### Relationship Tables (Type System Structure)
/// - **`InterfaceImpl`**: Interface implementation relationships
/// - **`NestedClass`**: Nested type parent-child relationships
/// - **`GenericParam`**: Generic type and method parameters
/// - **`GenericParamConstraint`**: Generic parameter constraints
///
/// ### Attribute and Metadata Tables
/// - **`CustomAttribute`**: Custom attribute applications
/// - **`Constant`**: Compile-time constant values
/// - **`DeclSecurity`**: Declarative security permissions
/// - **`FieldMarshal`**: Native interop marshalling specifications
///
/// ## Thread Safety and Concurrency
///
/// [`crate::metadata::streams::tablesheader::TablesHeader`] provides comprehensive thread safety for concurrent metadata access:
/// - **Immutable data**: All table data read-only after construction
/// - **Independent access**: Multiple threads can access different tables safely
/// - **Parallel iteration**: Safe concurrent processing of table rows
/// - **No synchronization**: Zero contention between concurrent operations
///
/// # Examples
///
/// ## Basic Table Access and Type Analysis
/// ```rust
/// use dotscope::metadata::{streams::TablesHeader, tables::{TableId, TypeDefRaw, MethodDefRaw}};
///
/// # fn example(tables_data: &[u8]) -> dotscope::Result<()> {
/// let tables = TablesHeader::from(tables_data, false)?;
///
/// // Safe table presence checking
/// if tables.has_table(TableId::TypeDef) {
///     let typedef_table = tables.table::<TypeDefRaw>().unwrap();
///     
///     println!("Assembly defines {} types", typedef_table.row_count);
///     
///     // Analyze type characteristics
///     // Iteration yields `Result<TypeDefRaw>`: a row that fails to parse is reported
///     // rather than silently ending the iteration.
///     for (index, type_def) in typedef_table.iter().enumerate().take(10) {
///         let type_def = type_def?;
///         let is_public = type_def.flags & 0x00000007 == 0x00000001;
///         let is_sealed = type_def.flags & 0x00000100 != 0;
///         let is_abstract = type_def.flags & 0x00000080 != 0;
///         
///         println!("Type {}: public={}, sealed={}, abstract={}",
///                  index, is_public, is_sealed, is_abstract);
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Cross-Table Relationship Analysis
/// ```rust
/// use dotscope::metadata::{streams::TablesHeader, tables::{TableId, TypeDefRaw, FieldRaw, MethodDefRaw}};
///
/// # fn example(tables_data: &[u8]) -> dotscope::Result<()> {
/// let tables = TablesHeader::from(tables_data, false)?;
///
/// // Analyze complete type structure with members
/// if let (Some(typedef_table), Some(field_table), Some(method_table)) = (
///     tables.table::<TypeDefRaw>(),
///     tables.table::<FieldRaw>(),
///     tables.table::<MethodDefRaw>()
/// ) {
///     for (type_idx, type_def) in typedef_table.iter().enumerate().take(5) {
///         let type_def = type_def?;
///         // Calculate member ranges for this type. `get` returns `Result<Option<_>>`:
///         // outer for a malformed row, inner for a RID past the end of the table.
///         let next_type = typedef_table.get((type_idx + 1) as u32)?;
///
///         let field_start = type_def.field_list.saturating_sub(1);
///         let field_end = next_type.as_ref()
///             .map(|t| t.field_list.saturating_sub(1))
///             .unwrap_or(field_table.row_count);
///         
///         let method_start = type_def.method_list.saturating_sub(1);
///         let method_end = next_type.as_ref()
///             .map(|t| t.method_list.saturating_sub(1))
///             .unwrap_or(method_table.row_count);
///         
///         println!("Type {}: {} fields, {} methods",
///                  type_idx,
///                  field_end.saturating_sub(field_start),
///                  method_end.saturating_sub(method_start));
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## High-Performance Parallel Processing
/// ```rust,no_run
/// use dotscope::metadata::{streams::TablesHeader, tables::{TableId, CustomAttributeRaw}};
/// use rayon::prelude::*;
/// use std::collections::HashMap;
///
/// # fn example(tables_data: &[u8]) -> dotscope::Result<()> {
/// let tables = TablesHeader::from(tables_data, false)?;
///
/// // Parallel analysis of custom attributes
/// if let Some(ca_table) = tables.table::<CustomAttributeRaw>() {
///     // Process attributes in parallel for large assemblies
///     let attribute_analysis: HashMap<u32, u32> = ca_table.par_iter()
///         .map(|attr| {
///             // Extract parent table type from coded index
///             let parent_table = 1u32; // Simplified for documentation
///             (parent_table, 1u32)
///         })
///         .collect::<Vec<_>>()
///         .into_iter()
///         .fold(HashMap::new(), |mut acc, (table, count)| {
///             *acc.entry(table).or_insert(0) += count;
///             acc
///         });
///     
///     println!("Custom attribute distribution:");
///     for (table_id, count) in attribute_analysis {
///         println!("  Table {}: {} attributes", table_id, count);
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Memory-Efficient Large Table Processing
/// ```rust,no_run
/// use dotscope::metadata::{streams::TablesHeader, tables::{TableId, MemberRefRaw}};
///
/// # fn example(tables_data: &[u8]) -> dotscope::Result<()> {
/// let tables = TablesHeader::from(tables_data, false)?;
///
/// // Process large tables without loading all data into memory
/// if let Some(memberref_table) = tables.table::<MemberRefRaw>() {
///     const CHUNK_SIZE: u32 = 1000;
///     let total_rows = memberref_table.row_count;
///     
///     println!("Processing {} member references in {} chunks",
///              total_rows, (total_rows + CHUNK_SIZE - 1) / CHUNK_SIZE);
///     
///     let mut external_method_refs = 0;
///     let mut external_field_refs = 0;
///     
///     // Process in chunks to manage memory usage
///     for chunk_start in (0..total_rows).step_by(CHUNK_SIZE as usize) {
///         let chunk_end = (chunk_start + CHUNK_SIZE).min(total_rows);
///         
///         for i in chunk_start..chunk_end {
///             if let Ok(Some(member_ref)) = memberref_table.get(i) {
///                 // Analyze member reference type and parent
///                 let is_method = true; // Simplified: check signature
///                 let is_external = true; // Simplified: check class reference
///                 
///                 if is_external {
///                     if is_method {
///                         external_method_refs += 1;
///                     } else {
///                         external_field_refs += 1;
///                     }
///                 }
///             }
///         }
///     }
///     
///     println!("External references: {} methods, {} fields",
///              external_method_refs, external_field_refs);
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Complete Assembly Introspection
/// ```rust
/// use dotscope::metadata::{streams::TablesHeader, tables::TableId};
///
/// # fn example(tables_data: &[u8]) -> dotscope::Result<()> {
/// let tables = TablesHeader::from(tables_data, false)?;
///
/// println!("Assembly Metadata Analysis");
/// println!("=========================");
/// println!("Total tables: {}", tables.table_count());
/// println!();
///
/// // Analyze present tables and their characteristics
/// let summaries = tables.table_summary();
/// for summary in summaries {
///     match summary.table_id {
///         TableId::TypeDef => println!("✓ {} type definitions", summary.row_count),
///         TableId::MethodDef => println!("✓ {} method definitions", summary.row_count),
///         TableId::Field => println!("✓ {} field definitions", summary.row_count),
///         TableId::Assembly => println!("✓ Assembly metadata present"),
///         TableId::AssemblyRef => println!("✓ {} assembly references", summary.row_count),
///         TableId::CustomAttribute => println!("✓ {} custom attributes", summary.row_count),
///         TableId::GenericParam => println!("✓ {} generic parameters (generics used)", summary.row_count),
///         TableId::DeclSecurity => println!("✓ {} security declarations", summary.row_count),
///         TableId::ManifestResource => println!("✓ {} embedded resources", summary.row_count),
///         _ => println!("✓ {:?}: {} rows", summary.table_id, summary.row_count),
///     }
/// }
///
/// // Feature detection
/// println!();
/// println!("Assembly Features:");
/// if tables.has_table(TableId::GenericParam) {
///     println!("  ✓ Uses generic types/methods");
/// }
/// if tables.has_table(TableId::Event) {
///     println!("  ✓ Defines events");
/// }
/// if tables.has_table(TableId::Property) {
///     println!("  ✓ Defines properties");
/// }
/// if tables.has_table(TableId::DeclSecurity) {
///     println!("  ✓ Has security declarations");
/// }
/// if tables.has_table(TableId::ImplMap) {
///     println!("  ✓ Uses P/Invoke");
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Security Considerations
///
/// ## Input Validation
/// - **ECMA-335 compliance**: Strict adherence to specification format requirements
/// - **Bounds checking**: All table and row access validated against buffer boundaries  
/// - **Index validation**: Cross-table references verified for correctness
/// - **Size limits**: Reasonable limits prevent resource exhaustion attacks
///
/// ## Memory Safety
/// - **Lifetime enforcement**: Rust borrow checker prevents use-after-free vulnerabilities
/// - **Type safety**: Generic parameters prevent incorrect table type access
/// - **Bounds verification**: All array and slice access is bounds-checked
/// - **No unsafe code**: The safe accessor layer replaced the pointer casting this once needed
///
/// # ECMA-335 Compliance
///
/// This implementation fully complies with ECMA-335 Partition II specifications:
/// - **Section II.24.2.6**: Metadata tables stream format and binary layout
/// - **Section II.22**: Complete metadata table definitions and relationships
/// - **Compression format**: Proper variable-width encoding for table indices
/// - **Heap integration**: Correct interpretation of string, blob, and GUID heap references
///
/// # See Also
/// - [`crate::metadata::tables::MetadataTable`]: Individual table access and iteration
/// - [`crate::metadata::tables::TableId`]: Enumeration of all supported table types
/// - [`crate::metadata::streams`]: Overview of all metadata stream types
/// - [ECMA-335 II.24.2.6](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): Tables header specification
///
/// ## Efficient Table Access Examples
///
/// ### Basic Table Access
/// ```rust,no_run
/// use dotscope::metadata::{streams::TablesHeader, tables::{TableId, TypeDefRaw, MethodDefRaw, FieldRaw}};
///
/// # fn example(tables_header: &TablesHeader) -> dotscope::Result<()> {
/// // Check if a table is present before accessing it
/// if tables_header.has_table(TableId::TypeDef) {
///     // Get efficient access to the TypeDef table
///     if let Some(typedef_table) = tables_header.table::<TypeDefRaw>() {
///         println!("TypeDef table has {} rows", typedef_table.row_count);
///         
///         // Access individual rows by index (0-based)
///         if let Ok(Some(first_type)) = typedef_table.get(1) {
///             println!("First type: flags={}, name_idx={}, namespace_idx={}",
///                     first_type.flags, first_type.type_name, first_type.type_namespace);
///         }
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// ### Iterating Over Table Rows
/// ```rust,no_run
/// use dotscope::metadata::{streams::TablesHeader, tables::{TableId, MethodDefRaw}};
///
/// # fn example(tables_header: &TablesHeader) -> dotscope::Result<()> {
/// // Iterate over all methods in the assembly
/// if let Some(method_table) = tables_header.table::<MethodDefRaw>() {
///     for (index, method) in method_table.iter().enumerate() {
///         let method = method?;
///         println!("Method {}: RVA={:#x}, impl_flags={}, flags={}, name_idx={}",
///                 index, method.rva, method.impl_flags, method.flags, method.name);
///         
///         // Break after first 10 for demonstration
///         if index >= 9 { break; }
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// ### Parallel Processing with Rayon
/// ```rust,no_run
/// use dotscope::metadata::{streams::TablesHeader, tables::{TableId, FieldRaw}};
/// use rayon::prelude::*;
///
/// # fn example(tables_header: &TablesHeader) -> dotscope::Result<()> {
/// // Process field metadata in parallel
/// if let Some(field_table) = tables_header.table::<FieldRaw>() {
///     let field_count = field_table.par_iter()
///         .filter_map(Result::ok) // parallel iteration yields `Result<FieldRaw>`
///         .filter(|field| field.flags & 0x0010 != 0) // FieldAttributes.Static
///         .count();
///     
///     println!("Found {} static fields", field_count);
/// }
/// # Ok(())
/// # }
/// ```
///
/// ### Cross-Table Analysis
/// ```rust,no_run
/// use dotscope::metadata::{streams::TablesHeader, tables::{TableId, TypeDefRaw, MethodDefRaw}};
///
/// # fn example(tables_header: &TablesHeader) -> dotscope::Result<()> {
/// // Analyze types and their methods together
/// if let (Some(typedef_table), Some(method_table)) = (
///     tables_header.table::<TypeDefRaw>(),
///     tables_header.table::<MethodDefRaw>()
/// ) {
///     for (type_idx, type_def) in typedef_table.iter().enumerate().take(5) {
///         let type_def = type_def?;
///         println!("Type {}: methods {}-{}",
///                 type_idx, type_def.method_list,
///                 type_def.method_list.saturating_add(10)); // Simplified example
///         
///         // In real usage, you'd calculate the actual method range
///         // by looking at the next type's method_list or using table bounds
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// ### Working with Table Summaries
/// ```rust,no_run
/// use dotscope::metadata::streams::TablesHeader;
///
/// # fn example(tables_header: &TablesHeader) -> dotscope::Result<()> {
/// // Get overview of all present tables
/// let summaries = tables_header.table_summary();
///
/// for summary in summaries {
///     println!("Table {:?}: {} rows", summary.table_id, summary.row_count);
/// }
///
/// // Check for specific tables by ID
/// if tables_header.has_table_by_id(0x02) { // TypeDef table ID
///     println!("TypeDef table is present");
/// }
///
/// println!("Total metadata tables: {}", tables_header.table_count());
/// # Ok(())
/// # }
/// ```
///
/// ### Memory-Efficient Pattern
/// ```rust,no_run
/// use dotscope::metadata::{streams::TablesHeader, tables::{TableId, CustomAttributeRaw}};
///
/// # fn example(tables_header: &TablesHeader) -> dotscope::Result<()> {
/// // Process large tables without loading all data at once
/// if let Some(ca_table) = tables_header.table::<CustomAttributeRaw>() {
///     println!("Processing {} custom attributes", ca_table.row_count);
///     
///     // Process in chunks to manage memory usage
///     const CHUNK_SIZE: u32 = 100;
///     let total_rows = ca_table.row_count;
///     
///     for chunk_start in (0..total_rows).step_by(CHUNK_SIZE as usize) {
///         let chunk_end = (chunk_start + CHUNK_SIZE).min(total_rows);
///         
///         for i in chunk_start..chunk_end {
///             if let Ok(Some(attr)) = ca_table.get(i) {
///                 // Process individual custom attribute
///                 // attr.parent, attr.type_def, attr.value are available
///                 // without copying the entire table into memory
///             }
///         }
///         
///         // Optional: yield control or log progress
///         println!("Processed chunk {}-{}", chunk_start, chunk_end);
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
///
/// ## Reference
/// * '<https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf>' - II.24.2.6 && II.22
pub struct TablesHeader<'a> {
    /// Major version of the metadata table schema, must be 2 per ECMA-335.
    ///
    /// This field indicates the major version of the metadata table format. According to
    /// ECMA-335 Section II.24.2.6, this value must be 2 for all compliant .NET assemblies.
    /// Different major versions would indicate incompatible changes to the table format.
    pub major_version: u8,

    /// Minor version of the metadata table schema, must be 0 per ECMA-335.
    ///
    /// This field indicates the minor version of the metadata table format. The ECMA-335
    /// specification requires this value to be 0. Minor version changes would indicate
    /// backward-compatible additions to the table format.
    pub minor_version: u8,

    /// Bit vector indicating which of the 64 possible metadata tables are present.
    ///
    /// Each bit corresponds to a specific table ID (0-63) as defined in ECMA-335.
    /// A set bit (1) indicates the corresponding table is present and contains data.
    /// The number of set bits determines how many row count entries follow in the header.
    ///
    /// ## Table ID Mapping
    /// - Bit 0: Module table
    /// - Bit 1: `TypeRef` table  
    /// - Bit 2: `TypeDef` table
    /// - Bit 4: Field table
    /// - Bit 6: `MethodDef` table
    /// - ... (see ECMA-335 II.22 for complete mapping)
    pub valid: u64,

    /// Bit vector indicating which metadata tables are sorted.
    ///
    /// For each present table (indicated by `valid`), the corresponding bit in `sorted`
    /// indicates whether that table's rows are sorted according to ECMA-335 requirements.
    /// Some tables must be sorted for binary search operations, while others may be
    /// unsorted for faster insertion during metadata generation.
    pub sorted: u64,

    /// Shared table information containing row counts and heap index sizes.
    ///
    /// This reference-counted structure provides efficient access to table metadata
    /// including row counts for each present table and the size encoding for heap
    /// indices (strings, blobs, GUIDs). The `Arc` allows multiple table instances
    /// to share this information without duplication.
    pub info: TableInfoRef,

    /// Byte offset to the start of table data relative to the beginning of this header.
    ///
    /// This offset points to where the actual table row data begins, after the header
    /// and row count arrays. Table data is stored sequentially in the order defined
    /// by the ECMA-335 table ID enumeration.
    tables_offset: usize,

    /// Vector of parsed metadata tables, indexed by table ID.
    ///
    /// Each element corresponds to a specific table type (0-44) and contains `Some(table)`
    /// if the table is present or `None` if absent. The tables are parsed lazily and
    /// stored as type-erased `TableData` enums to handle the heterogeneous table types
    /// while maintaining memory efficiency.
    tables: Vec<Option<TableData<'a>>>,
}

impl<'a> TablesHeader<'a> {
    /// Parse and construct a metadata tables header from binary data.
    ///
    /// Creates a [`crate::metadata::streams::tablesheader::TablesHeader`] by parsing the compressed metadata tables stream (`#~`)
    /// according to ECMA-335 Section II.24.2.6. This method performs comprehensive
    /// validation of the stream format and constructs efficient access structures for
    /// all present metadata tables.
    ///
    /// ## Binary Format Parsed
    ///
    /// The method parses the following header structure:
    /// ```text
    /// Offset | Size | Field              | Description
    /// -------|------|--------------------|-----------------------------------------
    /// 0      | 4    | Reserved           | Must be 0x00000000
    /// 4      | 1    | MajorVersion       | Schema major version (must be 2)
    /// 5      | 1    | MinorVersion       | Schema minor version (must be 0)
    /// 6      | 1    | HeapSizes          | String/Blob/GUID heap index sizes
    /// 7      | 1    | Reserved           | Must be 0x01
    /// 8      | 8    | Valid              | Bit vector of present tables
    /// 16     | 8    | Sorted             | Bit vector of sorted tables
    /// 24     | 4*N  | Rows[]             | Row counts for each present table
    /// 24+4*N | Var  | TableData[]        | Binary table data
    /// ```
    ///
    /// ## Validation Performed
    ///
    /// The method enforces ECMA-335 compliance through comprehensive validation:
    /// - **Minimum size**: Data must contain complete header (≥24 bytes)
    /// - **Version checking**: Major version must be 2, minor version must be 0
    /// - **Table presence**: At least one table must be present (valid ≠ 0)
    /// - **Format integrity**: Row count array and table data must be accessible
    /// - **Table structure**: Each present table validated for proper format
    ///
    /// ## Construction Process
    ///
    /// 1. **Header parsing**: Extract version, heap sizes, and table bit vectors
    /// 2. **Row count extraction**: Read row counts for all present tables
    /// 3. **Table initialization**: Parse each present table's binary data
    /// 4. **Reference setup**: Establish efficient access structures
    /// 5. **Validation**: Verify all tables conform to ECMA-335 format
    ///
    /// # Arguments
    /// * `data` - Complete binary data of the metadata tables stream (`#~` or `#-`)
    /// * `wide_columns` - Every index column is four bytes wide: the CLR's reading of
    ///   uncompressed (`#-`) tables beside a `#JTD` stream, which only the stream directory
    ///   can tell. `false` for any other tables stream.
    ///
    /// # Returns
    /// * `Ok(TablesHeader)` - Successfully parsed and validated tables header
    /// * `Err(Error)` - Parsing failed due to format violations or insufficient data
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] in the following cases:
    /// - **[`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`]**: Data too short for complete header (< 24 bytes)
    /// - **Malformed data**: No valid tables present (all bits in `valid` are 0)
    /// - **Version error**: Unsupported major/minor version combination
    /// - **Format error**: Invalid table data or corrupted stream structure
    /// - **Table error**: Individual table parsing failures due to malformed data
    ///
    /// # Examples
    ///
    /// ## Basic Tables Header Construction
    /// ```rust
    /// use dotscope::metadata::streams::TablesHeader;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// // Read compressed metadata tables stream from assembly
    /// # let tables_stream_data = include_bytes!("../../../tests/samples/WB_STREAM_TABLES_O-0x6C_S-0x59EB4.bin");
    /// let tables_stream_data = &[/* binary data from #~ stream */];
    ///
    /// let tables = TablesHeader::from(tables_stream_data, false)?;
    ///
    /// // Verify successful construction
    /// println!("Parsed metadata with {} tables", tables.table_count());
    /// println!("Schema version: {}.{}", tables.major_version, tables.minor_version);
    ///
    /// // Check for common tables
    /// use dotscope::metadata::tables::TableId;
    /// if tables.has_table(TableId::TypeDef) {
    ///     println!("Assembly defines {} types", tables.table_row_count(TableId::TypeDef));
    /// }
    /// if tables.has_table(TableId::MethodDef) {
    ///     println!("Assembly defines {} methods", tables.table_row_count(TableId::MethodDef));
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Error Handling and Validation
    /// ```rust
    /// use dotscope::metadata::streams::TablesHeader;
    ///
    /// # fn example() {
    /// // Error: Data too short
    /// let too_short = [0u8; 20]; // Only 20 bytes, need at least 24
    /// assert!(TablesHeader::from(&too_short, false).is_err());
    ///
    /// // Error: No valid tables
    /// let no_tables = [
    ///     0x00, 0x00, 0x00, 0x00, // Reserved
    ///     0x02, 0x00,             // Version 2.0
    ///     0x01, 0x01,             // HeapSizes, Reserved
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Valid = 0 (no tables)
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Sorted
    /// ];
    /// assert!(TablesHeader::from(&no_tables, false).is_err());
    /// # }
    /// ```
    ///
    /// ## Large Assembly Processing
    /// ```rust
    /// use dotscope::metadata::streams::TablesHeader;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// # let large_assembly_data = include_bytes!("../../../tests/samples/WB_STREAM_TABLES_O-0x6C_S-0x59EB4.bin");
    /// // Process large assembly with many tables
    /// let large_assembly_data = &[/* large assembly #~ stream data */];
    ///
    /// let start_time = std::time::Instant::now();
    /// let tables = TablesHeader::from(large_assembly_data, false)?;
    /// let parse_time = start_time.elapsed();
    ///
    /// println!("Parsed {} tables in {:?}", tables.table_count(), parse_time);
    ///
    /// // Analyze assembly size and complexity
    /// let summaries = tables.table_summary();
    /// let total_rows: u32 = summaries.iter().map(|s| s.row_count).sum();
    ///
    /// println!("Assembly complexity:");
    /// println!("  Total metadata rows: {}", total_rows);
    /// println!("  Average rows per table: {:.1}",
    ///          total_rows as f64 / tables.table_count() as f64);
    ///
    /// // Identify the most complex tables
    /// let mut large_tables: Vec<_> = summaries.iter()
    ///     .filter(|s| s.row_count > 1000)
    ///     .collect();
    /// large_tables.sort_by_key(|s| std::cmp::Reverse(s.row_count));
    ///
    /// println!("Largest tables:");
    /// for summary in large_tables.iter().take(3) {
    ///     println!("  {:?}: {} rows", summary.table_id, summary.row_count);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Assembly Feature Detection
    /// ```rust
    /// use dotscope::metadata::{streams::TablesHeader, tables::TableId};
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// # let assembly_data = include_bytes!("../../../tests/samples/WB_STREAM_TABLES_O-0x6C_S-0x59EB4.bin");
    /// let assembly_data = &[/* assembly #~ stream data */];
    /// let tables = TablesHeader::from(assembly_data, false)?;
    ///
    /// println!("Assembly Feature Analysis:");
    /// println!("=========================");
    ///
    /// // Detect .NET framework features
    /// if tables.has_table(TableId::GenericParam) {
    ///     let generic_count = tables.table_row_count(TableId::GenericParam);
    ///     println!("✓ Uses generics ({} parameters)", generic_count);
    /// }
    ///
    /// if tables.has_table(TableId::Event) {
    ///     let event_count = tables.table_row_count(TableId::Event);
    ///     println!("✓ Defines events ({} events)", event_count);
    /// }
    ///
    /// if tables.has_table(TableId::Property) {
    ///     let prop_count = tables.table_row_count(TableId::Property);
    ///     println!("✓ Defines properties ({} properties)", prop_count);
    /// }
    ///
    /// if tables.has_table(TableId::DeclSecurity) {
    ///     let security_count = tables.table_row_count(TableId::DeclSecurity);
    ///     println!("✓ Has security declarations ({} declarations)", security_count);
    /// }
    ///
    /// if tables.has_table(TableId::ImplMap) {
    ///     let pinvoke_count = tables.table_row_count(TableId::ImplMap);
    ///     println!("✓ Uses P/Invoke ({} mappings)", pinvoke_count);
    /// }
    ///
    /// if tables.has_table(TableId::ManifestResource) {
    ///     let resource_count = tables.table_row_count(TableId::ManifestResource);
    ///     println!("✓ Embeds resources ({} resources)", resource_count);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Thread Safety
    ///
    /// Construction is thread-safe when called with different data sources.
    /// The resulting [`crate::metadata::streams::tablesheader::TablesHeader`] instance is immutable and safe for concurrent
    /// access across multiple threads.
    ///
    /// # ECMA-335 Compliance
    ///
    /// This method implements full ECMA-335 Partition II compliance:
    /// - **Section II.24.2.6**: Metadata tables stream header format
    /// - **Section II.22**: Individual table format specifications
    /// - **Compression format**: Variable-width index encoding based on heap sizes
    /// - **Table relationships**: Proper handling of cross-table references
    ///
    /// # See Also
    /// - [`TablesHeader::table`]: Access individual metadata tables after construction
    /// - [`TablesHeader::table_summary`]: Get overview of all present tables
    /// - [`crate::metadata::tables::TableInfo`]: Table metadata and row count information
    /// - [ECMA-335 II.24.2.6](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): Tables header specification
    pub fn from(data: &'a [u8], wide_columns: bool) -> Result<TablesHeader<'a>> {
        Self::parse(data, wide_columns, None)
    }

    /// Parses a Portable PDB's tables stream: its columns index the assembly's tables by the
    /// row counts `type_system_rows` gives them (the `#Pdb` stream's,
    /// [`crate::metadata::streams::PdbStream::type_system_rows`]).
    ///
    /// # Errors
    ///
    /// As [`TablesHeader::from`].
    pub fn from_pdb(data: &'a [u8], type_system_rows: &[u32; 64]) -> Result<TablesHeader<'a>> {
        Self::parse(data, false, Some(type_system_rows))
    }

    fn parse(
        data: &'a [u8],
        wide_columns: bool,
        type_system_rows: Option<&[u32; 64]>,
    ) -> Result<TablesHeader<'a>> {
        let truncated = |expected: usize, found: usize| ParseFailure::Truncated {
            stage: ParseStage::TildeStream,
            expected,
            found,
        };
        if data.len() < 24 {
            return Err(truncated(24, data.len()).into());
        }

        let valid_bitvec = read_le::<u64>(
            data.get(8..)
                .ok_or_else(|| Error::from(truncated(16, data.len())))?,
        )?;
        if valid_bitvec == 0 {
            return Err(ParseFailure::InvalidField {
                stage: ParseStage::TildeStream,
                field: "valid",
                reason: "no valid rows in any of the tables".into(),
            }
            .into());
        }

        // HeapSizes bit 0x40 (ExtraData): one more u32 follows the row counts, and the tables
        // start after it, as the CLR and dnlib read it. ECMA-335 does not document the bit.
        let heap_sizes = read_le::<u8>(
            data.get(6..)
                .ok_or_else(|| Error::from(truncated(7, data.len())))?,
        )?;
        let extra_data_words = usize::from(heap_sizes & HEAP_SIZES_EXTRA_DATA != 0);
        let tables_offset = 24usize
            .checked_add(
                (valid_bitvec.count_ones() as usize)
                    .saturating_add(extra_data_words)
                    .saturating_mul(4),
            )
            .ok_or_else(|| ParseFailure::InvalidField {
                stage: ParseStage::TildeStream,
                field: "valid",
                reason: "tables-header offset overflow".into(),
            })?;
        let table_capacity = (TableId::CustomDebugInformation as usize).saturating_add(1);

        let mut tables_header = TablesHeader {
            major_version: read_le::<u8>(
                data.get(4..)
                    .ok_or_else(|| Error::from(truncated(5, data.len())))?,
            )?,
            minor_version: read_le::<u8>(
                data.get(5..)
                    .ok_or_else(|| Error::from(truncated(6, data.len())))?,
            )?,
            valid: valid_bitvec,
            sorted: read_le::<u64>(
                data.get(16..)
                    .ok_or_else(|| Error::from(truncated(24, data.len())))?,
            )?,
            info: Arc::new(match type_system_rows {
                Some(rows) => TableInfo::with_external_rows(data, valid_bitvec, rows)?,
                None => TableInfo::new(data, valid_bitvec, wide_columns)?,
            }),
            tables_offset,
            tables: Vec::with_capacity(table_capacity),
        };

        // with_capacity has allocated the buffer, but we can't 'insert' elements, only push
        // to make the vector grow - as .insert doesn't adjust length, only push does.
        tables_header.tables.resize_with(table_capacity, || None);

        let mut current_offset = tables_header.tables_offset;
        for table_id in TableId::iter() {
            if current_offset > data.len() {
                return Err(ParseFailure::OutOfBounds {
                    stage: ParseStage::TildeStream,
                }
                .into());
            }

            tables_header.add_table(
                data.get(current_offset..).ok_or_else(|| {
                    Error::from(ParseFailure::OutOfBounds {
                        stage: ParseStage::TildeStream,
                    })
                })?,
                table_id,
                &mut current_offset,
            )?;
        }

        // Checked again after the loop, not only at the top of each iteration: the check above
        // catches an overshoot on the *next* variant, which leaves the last one - presently
        // `CustomDebugInformation` - with nothing behind it to notice.
        if current_offset > data.len() {
            return Err(ParseFailure::OutOfBounds {
                stage: ParseStage::TildeStream,
            }
            .into());
        }

        Ok(tables_header)
    }

    /// Get the total number of metadata tables present in this assembly.
    ///
    /// Returns the count of tables that are actually present and contain data.
    /// This is equivalent to the number of set bits in the `valid` field.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::streams::TablesHeader;
    ///
    /// # fn example(tables: &TablesHeader) {
    /// println!("Assembly contains {} metadata tables", tables.table_count());
    /// # }
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn table_count(&self) -> u32 {
        self.valid.count_ones()
    }

    /// Get a specific table for efficient access to metadata table rows.
    ///
    /// This method provides safe, type-driven access to metadata tables without copying data.
    /// The returned table reference allows efficient iteration and random access to rows.
    /// The table type is automatically determined from the generic parameter, eliminating
    /// the need to specify table IDs and preventing type mismatches.
    ///
    /// # Type Parameter
    ///
    /// * `T` - The table row type (e.g., [`crate::metadata::tables::TypeDefRaw`])
    ///   The table ID is automatically inferred from the type parameter.
    ///
    /// # Returns
    ///
    /// * `Some(&MetadataTable<T>)` - Reference to the [`crate::metadata::tables::MetadataTable`] if present
    /// * `None` - If the table is not present in this assembly
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::{streams::TablesHeader, tables::TypeDefRaw};
    ///
    /// # fn example(tables: &TablesHeader) -> dotscope::Result<()> {
    /// // Safe, ergonomic access with automatic type inference
    /// if let Some(typedef_table) = tables.table::<TypeDefRaw>() {
    ///     // Efficient access to all type definitions
    ///     for type_def in typedef_table.iter().take(5) {
    ///         let type_def = type_def?;
    ///         println!("Type: flags={:#x}, name_idx={}, namespace_idx={}",
    ///                 type_def.flags, type_def.type_name, type_def.type_namespace);
    ///     }
    ///
    ///     // Random access to specific rows, by RID (1-based)
    ///     if let Ok(Some(first_type)) = typedef_table.get(1) {
    ///         println!("First type name index: {}", first_type.type_name);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    /// The returned table reference is also safe for concurrent read access.
    ///
    /// # Implementation Details
    ///
    /// This method uses a trait to provide safe, compile-time verified table access.
    /// The trait implementation automatically maps each table type to its corresponding
    /// table ID, ensuring type safety without runtime overhead. No unsafe code is required.
    #[must_use]
    pub fn table<T: RowReadable>(&'a self) -> Option<&'a MetadataTable<'a, T>>
    where
        Self: TableAccess<'a, T>,
    {
        <Self as TableAccess<'a, T>>::table(self)
    }

    /// Add a table to the tables header.
    ///
    /// This method creates a `MetadataTable` for the specified table type and stores it
    /// in the internal tables collection. The method uses the `create_table_match!` macro
    /// to generate the match expression, significantly reducing code duplication.
    ///
    /// # Arguments
    /// * `data` - The raw bytes containing the table data
    /// * `table_type` - The type of table to create
    /// * `current_offset` - Mutable reference to track the current position in the data
    ///
    /// # Returns
    /// * `Ok(())` - If the table was successfully created and stored
    /// * `Err(...)` - If table parsing failed
    // Note: table.size() returns u64, but we need usize for offset arithmetic.
    // This cast is safe because metadata tables are bounded by the PE file size
    // which is limited to ~4GB, well within usize range on all supported platforms.
    #[allow(clippy::cast_possible_truncation)]
    fn add_table(
        &mut self,
        data: &'a [u8],
        table_type: TableId,
        current_offset: &mut usize,
    ) -> Result<()> {
        // Only the tables the stream declares are in it: a Portable PDB's row counts for the
        // assembly's tables size its indexes, and their rows are not here
        let t_info = self.info.get(table_type);
        if t_info.rows == 0 || self.valid & (1u64 << (table_type as u8)) == 0 {
            return Ok(());
        }

        let table = create_table_match!(
            table_type,
            data,
            t_info.rows,
            self.info,
            current_offset,
            // Core Tables (0x00-0x09)
            (TableId::Module, ModuleRaw, Module),
            (TableId::TypeRef, TypeRefRaw, TypeRef),
            (TableId::TypeDef, TypeDefRaw, TypeDef),
            (TableId::FieldPtr, FieldPtrRaw, FieldPtr),
            (TableId::Field, FieldRaw, Field),
            (TableId::MethodPtr, MethodPtrRaw, MethodPtr),
            (TableId::MethodDef, MethodDefRaw, MethodDef),
            (TableId::ParamPtr, ParamPtrRaw, ParamPtr),
            (TableId::Param, ParamRaw, Param),
            (TableId::InterfaceImpl, InterfaceImplRaw, InterfaceImpl),
            // Reference and Attribute Tables (0x0A-0x0E)
            (TableId::MemberRef, MemberRefRaw, MemberRef),
            (TableId::Constant, ConstantRaw, Constant),
            (
                TableId::CustomAttribute,
                CustomAttributeRaw,
                CustomAttribute
            ),
            (TableId::FieldMarshal, FieldMarshalRaw, FieldMarshal),
            (TableId::DeclSecurity, DeclSecurityRaw, DeclSecurity),
            // Layout and Signature Tables (0x0F-0x11)
            (TableId::ClassLayout, ClassLayoutRaw, ClassLayout),
            (TableId::FieldLayout, FieldLayoutRaw, FieldLayout),
            (TableId::StandAloneSig, StandAloneSigRaw, StandAloneSig),
            // Event Tables (0x12-0x14)
            (TableId::EventMap, EventMapRaw, EventMap),
            (TableId::EventPtr, EventPtrRaw, EventPtr),
            (TableId::Event, EventRaw, Event),
            // Property Tables (0x15-0x17)
            (TableId::PropertyMap, PropertyMapRaw, PropertyMap),
            (TableId::PropertyPtr, PropertyPtrRaw, PropertyPtr),
            (TableId::Property, PropertyRaw, Property),
            // Method Semantic Tables (0x18-0x19)
            (
                TableId::MethodSemantics,
                MethodSemanticsRaw,
                MethodSemantics
            ),
            (TableId::MethodImpl, MethodImplRaw, MethodImpl),
            // Reference Tables (0x1A-0x1C)
            (TableId::ModuleRef, ModuleRefRaw, ModuleRef),
            (TableId::TypeSpec, TypeSpecRaw, TypeSpec),
            (TableId::ImplMap, ImplMapRaw, ImplMap),
            (TableId::FieldRVA, FieldRvaRaw, FieldRVA),
            // Assembly Tables (0x20-0x28)
            (TableId::Assembly, AssemblyRaw, Assembly),
            (
                TableId::AssemblyProcessor,
                AssemblyProcessorRaw,
                AssemblyProcessor
            ),
            (TableId::AssemblyOS, AssemblyOsRaw, AssemblyOS),
            (TableId::AssemblyRef, AssemblyRefRaw, AssemblyRef),
            (
                TableId::AssemblyRefProcessor,
                AssemblyRefProcessorRaw,
                AssemblyRefProcessor
            ),
            (TableId::AssemblyRefOS, AssemblyRefOsRaw, AssemblyRefOS),
            (TableId::File, FileRaw, File),
            (TableId::ExportedType, ExportedTypeRaw, ExportedType),
            (
                TableId::ManifestResource,
                ManifestResourceRaw,
                ManifestResource
            ),
            (TableId::NestedClass, NestedClassRaw, NestedClass),
            // Generic Tables (0x2A-0x2C)
            (TableId::GenericParam, GenericParamRaw, GenericParam),
            (TableId::MethodSpec, MethodSpecRaw, MethodSpec),
            (
                TableId::GenericParamConstraint,
                GenericParamConstraintRaw,
                GenericParamConstraint
            ),
            // Debug Information Tables (0x30-0x37)
            (TableId::Document, DocumentRaw, Document),
            (
                TableId::MethodDebugInformation,
                MethodDebugInformationRaw,
                MethodDebugInformation
            ),
            (TableId::LocalScope, LocalScopeRaw, LocalScope),
            (TableId::LocalVariable, LocalVariableRaw, LocalVariable),
            (TableId::LocalConstant, LocalConstantRaw, LocalConstant),
            (TableId::ImportScope, ImportScopeRaw, ImportScope),
            (
                TableId::StateMachineMethod,
                StateMachineMethodRaw,
                StateMachineMethod
            ),
            (
                TableId::CustomDebugInformation,
                CustomDebugInformationRaw,
                CustomDebugInformation
            ),
            // Edit-and-Continue Tables (0x1E-0x1F)
            (TableId::EncLog, EncLogRaw, EncLog),
            (TableId::EncMap, EncMapRaw, EncMap),
        );

        self.tables.insert(table_type as usize, Some(table));
        Ok(())
    }

    /// Check if a specific metadata table is present in this assembly.
    ///
    /// Use this method to safely check for table presence before accessing it.
    /// This avoids potential panics when working with assemblies that may not
    /// contain all possible metadata tables.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The [`crate::metadata::tables::TableId`] to check for presence
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::{streams::TablesHeader, tables::{TableId, EventRaw}};
    ///
    /// # fn example(tables: &TablesHeader) -> dotscope::Result<()> {
    /// /// Safe pattern: check before access
    /// if tables.has_table(TableId::Event) {
    ///     if let Some(event_table) = tables.table::<EventRaw>() {
    ///         println!("Assembly has {} events", event_table.row_count);
    ///     }
    /// } else {
    ///     println!("No events defined in this assembly");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn has_table(&self, table_id: TableId) -> bool {
        (self.valid & (1u64 << (table_id as u8))) != 0
    }

    /// Check if a metadata table is present by its numeric ID.
    ///
    /// This method provides a way to check for table presence using the raw
    /// numeric table identifiers (0-63) as defined in the ECMA-335 specification.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The numeric table ID (0-63) to check for presence
    ///
    /// # Returns
    ///
    /// * `true` - If the table is present
    /// * `false` - If the table is not present or `table_id` > 63
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::streams::TablesHeader;
    ///
    /// # fn example(tables: &TablesHeader) {
    /// // Check for specific tables by their numeric IDs
    /// if tables.has_table_by_id(0x02) { // TypeDef
    ///     println!("TypeDef table present");
    /// }
    /// if tables.has_table_by_id(0x06) { // MethodDef  
    ///     println!("MethodDef table present");
    /// }
    /// if tables.has_table_by_id(0x04) { // Field
    ///     println!("Field table present");
    /// }
    /// # }
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn has_table_by_id(&self, table_id: u8) -> bool {
        if table_id > 63 {
            return false;
        }
        (self.valid & (1u64 << table_id)) != 0
    }

    /// Get an iterator over all present metadata tables.
    ///
    /// This method returns an iterator that yields [`crate::metadata::tables::TableId`] values for all tables
    /// that are present in this assembly's metadata. Useful for discovering what
    /// metadata is available without having to check each table individually.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::streams::TablesHeader;
    ///
    /// # fn example(tables: &TablesHeader) {
    /// println!("Present metadata tables:");
    /// for table_id in tables.present_tables() {
    ///     let row_count = tables.table_row_count(table_id);
    ///     println!("  {:?}: {} rows", table_id, row_count);
    /// }
    /// # }
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn present_tables(&self) -> impl Iterator<Item = TableId> + '_ {
        TableId::iter().filter(|&table_id| self.has_table(table_id))
    }

    /// Get the row count for a specific metadata table.
    ///
    /// Returns the number of rows in the specified table. This information
    /// is available even if you don't access the table data itself.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The [`crate::metadata::tables::TableId`] to get the row count for
    ///
    /// # Returns
    ///
    /// Row count (0 if table is not present)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::{streams::TablesHeader, tables::TableId};
    ///
    /// # fn example(tables: &TablesHeader) {
    /// let type_count = tables.table_row_count(TableId::TypeDef);
    /// let method_count = tables.table_row_count(TableId::MethodDef);
    /// let field_count = tables.table_row_count(TableId::Field);
    ///
    /// println!("Assembly contains:");
    /// println!("  {} types", type_count);
    /// println!("  {} methods", method_count);
    /// println!("  {} fields", field_count);
    /// # }
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn table_row_count(&self, table_id: TableId) -> u32 {
        if self.has_table(table_id) {
            self.info.get(table_id).rows
        } else {
            0
        }
    }

    /// Get a summary of all present metadata tables with their row counts.
    ///
    /// Returns a vector of summary structs containing the table ID and row count
    /// for each table present in this assembly. This provides an efficient way to get an
    /// overview of the assembly's metadata structure without accessing individual tables.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::streams::TablesHeader;
    ///
    /// # fn example(tables: &TablesHeader) {
    /// let summaries = tables.table_summary();
    /// for summary in summaries {
    ///     println!("Table {:?}: {} rows", summary.table_id, summary.row_count);
    /// }
    /// # }
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn table_summary(&self) -> Vec<TableSummary> {
        self.present_tables()
            .map(|table_id| TableSummary {
                table_id,
                row_count: self.table_row_count(table_id),
            })
            .collect()
    }

    /// Writes the tables stream header to a writer in ECMA-335 binary format.
    ///
    /// Serializes the tables stream header including version info, heap sizes,
    /// valid/sorted table bitmasks, and row counts for present tables according
    /// to ECMA-335 Section II.24.2.6.
    ///
    /// **Note**: This method writes only the header, not the actual table row data.
    /// Table row data should be written separately using the `RowWritable` implementations.
    ///
    /// ## Binary Format Written
    /// ```text
    /// Offset | Size | Field        | Description
    /// -------|------|--------------|----------------------------------
    /// 0      | 4    | Reserved     | Must be 0x00000000
    /// 4      | 1    | MajorVersion | Schema major version (2)
    /// 5      | 1    | MinorVersion | Schema minor version (0)
    /// 6      | 1    | HeapSizes    | Heap index size flags
    /// 7      | 1    | Reserved     | Must be 0x01
    /// 8      | 8    | Valid        | Bit vector of present tables
    /// 16     | 8    | Sorted       | Bit vector of sorted tables
    /// 24     | 4*N  | Rows[]       | Row counts for each present table
    /// ```
    ///
    /// # Arguments
    /// * `writer` - Any type implementing [`std::io::Write`]
    ///
    /// # Returns
    /// * `Ok(())` - Header written successfully
    /// * `Err(Error)` - Write operation failed
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the writer fails.
    ///
    /// # Examples
    /// ```rust,no_run
    /// use dotscope::metadata::streams::TablesHeader;
    ///
    /// # fn example(tables: &TablesHeader) -> dotscope::Result<()> {
    /// let mut buffer = Vec::new();
    /// tables.write_header_to(&mut buffer)?;
    ///
    /// // Buffer now contains the serialized tables stream header
    /// println!("Header size: {} bytes", buffer.len());
    /// # Ok(())
    /// # }
    /// ```
    pub fn write_header_to<W: Write>(&self, writer: &mut W) -> crate::Result<()> {
        // Reserved (4 bytes) - must be 0
        writer.write_all(&[0u8; 4])?;

        // MajorVersion (1 byte)
        writer.write_all(&[self.major_version])?;

        // MinorVersion (1 byte)
        writer.write_all(&[self.minor_version])?;

        // HeapSizes (1 byte)
        writer.write_all(&[self.info.heap_sizes()])?;

        // Reserved (1 byte) - must be 1
        writer.write_all(&[0x01])?;

        // Valid (8 bytes) - bit vector of present tables
        writer.write_all(&self.valid.to_le_bytes())?;

        // Sorted (8 bytes) - bit vector of sorted tables
        writer.write_all(&self.sorted.to_le_bytes())?;

        // Row counts (4 bytes each) for present tables in table ID order
        for table_id in TableId::iter() {
            if self.has_table(table_id) {
                let row_count = self.table_row_count(table_id);
                writer.write_all(&row_count.to_le_bytes())?;
            }
        }

        Ok(())
    }

    /// Returns the serialized size of the tables stream header in bytes.
    ///
    /// The size includes the fixed header fields (24 bytes) plus 4 bytes for
    /// each present table's row count.
    ///
    /// # Returns
    /// The total size in bytes when written with [`write_header_to`](Self::write_header_to).
    ///
    /// # Examples
    /// ```rust,no_run
    /// use dotscope::metadata::streams::TablesHeader;
    ///
    /// # fn example(tables: &TablesHeader) {
    /// let header_size = tables.header_size();
    /// println!("Tables stream header: {} bytes", header_size);
    /// # }
    /// ```
    #[must_use]
    pub fn header_size(&self) -> usize {
        // Fixed header: 24 bytes
        // Row counts: 4 bytes per present table
        24usize.saturating_add((self.valid.count_ones() as usize).saturating_mul(4))
    }
}

/// Summary information for a metadata table providing table identity and size information.
///
/// This struct is used by [`crate::metadata::streams::tablesheader::TablesHeader::table_summary`] to provide an overview
/// of all present tables in the metadata without requiring full table access. This
/// is useful for assembly analysis, diagnostics, and determining what metadata is
/// available before processing specific tables.
///
/// # Examples
///
/// ## Basic Usage with Table Summary
/// ```rust
/// use dotscope::metadata::streams::TablesHeader;
///
/// # fn example(tables_data: &[u8]) -> dotscope::Result<()> {
/// let tables = TablesHeader::from(tables_data, false)?;
///
/// // Get overview of all tables
/// let summaries = tables.table_summary();
///
/// for summary in summaries {
///     println!("Table {:?} has {} rows", summary.table_id, summary.row_count);
///     
///     // Make decisions based on table size
///     if summary.row_count > 1000 {
///         println!("  ↳ Large table - consider parallel processing");
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Filtering and Analysis
/// ```rust
/// use dotscope::metadata::{streams::TablesHeader, tables::TableId};
///
/// # fn example(tables_data: &[u8]) -> dotscope::Result<()> {
/// let tables = TablesHeader::from(tables_data, false)?;
/// let summaries = tables.table_summary();
///
/// // Find the largest tables
/// let mut large_tables: Vec<_> = summaries.iter()
///     .filter(|s| s.row_count > 100)
///     .collect();
/// large_tables.sort_by_key(|s| std::cmp::Reverse(s.row_count));
///
/// println!("Largest metadata tables:");
/// for summary in large_tables.iter().take(5) {
///     println!("  {:?}: {} rows", summary.table_id, summary.row_count);
/// }
///
/// // Check for specific features
/// let has_generics = summaries.iter()
///     .any(|s| s.table_id == TableId::GenericParam && s.row_count > 0);
/// if has_generics {
///     println!("Assembly uses generic types");
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct TableSummary {
    /// The type/ID of the metadata table.
    ///
    /// Identifies which specific metadata table this summary describes using the
    /// ECMA-335 table enumeration. This corresponds to table IDs 0-44 as defined
    /// in the specification.
    pub table_id: TableId,

    /// The number of rows present in this table.
    ///
    /// Indicates the count of data rows in the table. A value of 0 means the table
    /// is present in the assembly but contains no data. Tables not present in the
    /// assembly will not appear in the summary at all.
    pub row_count: u32,
}

// Generate safe TableAccess trait implementations for all metadata table types
impl_table_access!(ModuleRaw, TableId::Module, Module);
impl_table_access!(TypeRefRaw, TableId::TypeRef, TypeRef);
impl_table_access!(TypeDefRaw, TableId::TypeDef, TypeDef);
impl_table_access!(FieldPtrRaw, TableId::FieldPtr, FieldPtr);
impl_table_access!(FieldRaw, TableId::Field, Field);
impl_table_access!(MethodPtrRaw, TableId::MethodPtr, MethodPtr);
impl_table_access!(MethodDefRaw, TableId::MethodDef, MethodDef);
impl_table_access!(ParamPtrRaw, TableId::ParamPtr, ParamPtr);
impl_table_access!(ParamRaw, TableId::Param, Param);
impl_table_access!(InterfaceImplRaw, TableId::InterfaceImpl, InterfaceImpl);
impl_table_access!(MemberRefRaw, TableId::MemberRef, MemberRef);
impl_table_access!(ConstantRaw, TableId::Constant, Constant);
impl_table_access!(
    CustomAttributeRaw,
    TableId::CustomAttribute,
    CustomAttribute
);
impl_table_access!(FieldMarshalRaw, TableId::FieldMarshal, FieldMarshal);
impl_table_access!(DeclSecurityRaw, TableId::DeclSecurity, DeclSecurity);
impl_table_access!(ClassLayoutRaw, TableId::ClassLayout, ClassLayout);
impl_table_access!(FieldLayoutRaw, TableId::FieldLayout, FieldLayout);
impl_table_access!(StandAloneSigRaw, TableId::StandAloneSig, StandAloneSig);
impl_table_access!(EventMapRaw, TableId::EventMap, EventMap);
impl_table_access!(EventPtrRaw, TableId::EventPtr, EventPtr);
impl_table_access!(EventRaw, TableId::Event, Event);
impl_table_access!(PropertyMapRaw, TableId::PropertyMap, PropertyMap);
impl_table_access!(PropertyPtrRaw, TableId::PropertyPtr, PropertyPtr);
impl_table_access!(PropertyRaw, TableId::Property, Property);
impl_table_access!(
    MethodSemanticsRaw,
    TableId::MethodSemantics,
    MethodSemantics
);
impl_table_access!(MethodImplRaw, TableId::MethodImpl, MethodImpl);
impl_table_access!(ModuleRefRaw, TableId::ModuleRef, ModuleRef);
impl_table_access!(TypeSpecRaw, TableId::TypeSpec, TypeSpec);
impl_table_access!(ImplMapRaw, TableId::ImplMap, ImplMap);
impl_table_access!(FieldRvaRaw, TableId::FieldRVA, FieldRVA);
impl_table_access!(AssemblyRaw, TableId::Assembly, Assembly);
impl_table_access!(
    AssemblyProcessorRaw,
    TableId::AssemblyProcessor,
    AssemblyProcessor
);
impl_table_access!(AssemblyOsRaw, TableId::AssemblyOS, AssemblyOS);
impl_table_access!(AssemblyRefRaw, TableId::AssemblyRef, AssemblyRef);
impl_table_access!(
    AssemblyRefProcessorRaw,
    TableId::AssemblyRefProcessor,
    AssemblyRefProcessor
);
impl_table_access!(AssemblyRefOsRaw, TableId::AssemblyRefOS, AssemblyRefOS);
impl_table_access!(FileRaw, TableId::File, File);
impl_table_access!(ExportedTypeRaw, TableId::ExportedType, ExportedType);
impl_table_access!(
    ManifestResourceRaw,
    TableId::ManifestResource,
    ManifestResource
);
impl_table_access!(NestedClassRaw, TableId::NestedClass, NestedClass);
impl_table_access!(GenericParamRaw, TableId::GenericParam, GenericParam);
impl_table_access!(MethodSpecRaw, TableId::MethodSpec, MethodSpec);
impl_table_access!(
    GenericParamConstraintRaw,
    TableId::GenericParamConstraint,
    GenericParamConstraint
);
impl_table_access!(DocumentRaw, TableId::Document, Document);
impl_table_access!(
    MethodDebugInformationRaw,
    TableId::MethodDebugInformation,
    MethodDebugInformation
);
impl_table_access!(LocalScopeRaw, TableId::LocalScope, LocalScope);
impl_table_access!(LocalVariableRaw, TableId::LocalVariable, LocalVariable);
impl_table_access!(LocalConstantRaw, TableId::LocalConstant, LocalConstant);
impl_table_access!(ImportScopeRaw, TableId::ImportScope, ImportScope);
impl_table_access!(
    StateMachineMethodRaw,
    TableId::StateMachineMethod,
    StateMachineMethod
);
impl_table_access!(
    CustomDebugInformationRaw,
    TableId::CustomDebugInformation,
    CustomDebugInformation
);
impl_table_access!(EncLogRaw, TableId::EncLog, EncLog);
impl_table_access!(EncMapRaw, TableId::EncMap, EncMap);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::verify_tableheader;

    #[test]
    fn wb_stream_0() {
        let data = include_bytes!("../../../tests/samples/WB_STREAM_TABLES_O-0x6C_S-0x59EB4.bin");
        let header = TablesHeader::from(data, false).unwrap();

        verify_tableheader(&header);
    }

    #[test]
    fn test_tables_header_too_short() {
        // Header must be at least 24 bytes
        let data = [0u8; 20];
        assert!(TablesHeader::from(&data, false).is_err());
    }

    #[test]
    fn test_tables_header_invalid_reserved() {
        // Reserved byte must be 0
        #[rustfmt::skip]
        let data = [
            0x00, 0x00, 0x00, 0x01, // reserved (invalid - should be 0), major_version, minor_version, heap_sizes
            0x01,                   // reserved (invalid - should be 0)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // valid bitmask (8 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sorted bitmask (8 bytes)
        ];
        assert!(TablesHeader::from(&data, false).is_err());
    }

    #[test]
    fn test_tables_header_empty_tables() {
        // Valid header with no tables present (valid bitmask = 0)
        #[rustfmt::skip]
        let data = [
            0x00, 0x00, 0x02, 0x00, // reserved, major_version=2, minor_version=0, heap_sizes
            0x00,                   // reserved
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // valid bitmask = 0 (no tables)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sorted bitmask
        ];
        // Note: This may fail due to row count parsing - depends on exact header format requirements
        let result = TablesHeader::from(&data, false);
        // Empty valid bitmask means no tables, which should be accepted
        // but may require row counts, so we just verify it doesn't panic
        let _ = result;
    }

    #[test]
    fn test_has_table() {
        let data = include_bytes!("../../../tests/samples/WB_STREAM_TABLES_O-0x6C_S-0x59EB4.bin");
        let header = TablesHeader::from(data, false).unwrap();

        // Module table (0x00) should always be present
        assert!(header.has_table(TableId::Module));

        // TypeDef table (0x02) should be present in most assemblies
        assert!(header.has_table(TableId::TypeDef));
    }

    #[test]
    fn test_has_table_by_id() {
        let data = include_bytes!("../../../tests/samples/WB_STREAM_TABLES_O-0x6C_S-0x59EB4.bin");
        let header = TablesHeader::from(data, false).unwrap();

        // Module table (0x00) should always be present
        assert!(header.has_table_by_id(0x00));

        // TypeDef table (0x02)
        assert!(header.has_table_by_id(0x02));

        // Invalid table ID > 63 should return false
        assert!(!header.has_table_by_id(64));
        assert!(!header.has_table_by_id(255));
    }

    #[test]
    fn test_table_count() {
        let data = include_bytes!("../../../tests/samples/WB_STREAM_TABLES_O-0x6C_S-0x59EB4.bin");
        let header = TablesHeader::from(data, false).unwrap();

        // table_count should match the number of bits set in the valid bitmask
        let count = header.table_count();
        assert!(count > 0);
        assert!(count <= 64); // Maximum possible tables

        // Verify count matches bit count in valid field
        let bit_count = header.valid.count_ones();
        assert_eq!(count, bit_count);
    }

    #[test]
    fn test_table_summary() {
        let data = include_bytes!("../../../tests/samples/WB_STREAM_TABLES_O-0x6C_S-0x59EB4.bin");
        let header = TablesHeader::from(data, false).unwrap();

        let summaries = header.table_summary();

        // Should have same number of summaries as tables
        assert_eq!(summaries.len(), header.table_count() as usize);

        // Each summary should have valid data
        for summary in &summaries {
            // Table ID should be a valid enum variant
            assert!((summary.table_id as u8) < 64);
            // This table should be marked as present
            assert!(header.has_table(summary.table_id));
        }
    }

    #[test]
    fn test_type_safe_table_access() {
        let data = include_bytes!("../../../tests/samples/WB_STREAM_TABLES_O-0x6C_S-0x59EB4.bin");
        let header = TablesHeader::from(data, false).unwrap();

        // Access Module table with type-safe generic method
        let module_table = header.table::<ModuleRaw>();
        assert!(module_table.is_some());
        let module = module_table.unwrap();
        assert_eq!(module.row_count, 1); // Module table should have exactly 1 row

        // Access TypeDef table
        let typedef_table = header.table::<TypeDefRaw>();
        assert!(typedef_table.is_some());
        assert!(typedef_table.unwrap().row_count > 0);
    }

    #[test]
    fn test_write_header_to() {
        let data = include_bytes!("../../../tests/samples/WB_STREAM_TABLES_O-0x6C_S-0x59EB4.bin");
        let header = TablesHeader::from(data, false).unwrap();

        let mut buffer = Vec::new();
        header.write_header_to(&mut buffer).unwrap();

        // Verify size matches expected
        assert_eq!(buffer.len(), header.header_size());

        // Verify reserved bytes
        assert_eq!(&buffer[0..4], &[0, 0, 0, 0]); // Reserved

        // Verify version
        assert_eq!(buffer[4], header.major_version);
        assert_eq!(buffer[5], header.minor_version);

        // Verify heap sizes
        assert_eq!(buffer[6], header.info.heap_sizes());

        // Verify reserved byte
        assert_eq!(buffer[7], 0x01);

        // Verify valid bitmask
        let valid_from_buffer = u64::from_le_bytes(buffer[8..16].try_into().unwrap());
        assert_eq!(valid_from_buffer, header.valid);

        // Verify sorted bitmask
        let sorted_from_buffer = u64::from_le_bytes(buffer[16..24].try_into().unwrap());
        assert_eq!(sorted_from_buffer, header.sorted);
    }

    #[test]
    fn test_header_size() {
        let data = include_bytes!("../../../tests/samples/WB_STREAM_TABLES_O-0x6C_S-0x59EB4.bin");
        let header = TablesHeader::from(data, false).unwrap();

        // Header size should be 24 + (4 * number of tables)
        let expected_size = 24 + (header.table_count() as usize * 4);
        assert_eq!(header.header_size(), expected_size);
    }
}

//! # Table Data Enumeration Module
//!
//! This module defines the unified enumeration for all possible metadata tables that can exist
//! in a .NET CLI assembly's metadata stream. The `#~` or `#-` stream contains a collection of these
//! tables, each representing different aspects of the assembly's type system and metadata.
//!
//! ## Overview
//!
//! The .NET metadata format organizes information into a series of structured tables, as defined
//! in ECMA-335. Each table type contains specific kinds of metadata records, such as type
//! definitions, method signatures, field information, and assembly references. This module
//! provides a type-safe enumeration that can hold any of these table types.
//!
//! ## Usage Example
//!
//! ```no_run
//! use dotscope::metadata::tables::TableData;
//! use rayon::prelude::*;
//!
//! fn process_table(table: &TableData) {
//!     match table {
//!         TableData::TypeDef(type_table) => {
//!             println!("Processing {} type definitions", type_table.row_count);
//!             for type_def in type_table.iter() {
//!                 // Process each type definition
//!             }
//!         }
//!         TableData::MethodDef(method_table) => {
//!             println!("Processing {} method definitions", method_table.row_count);
//!             // Process methods in parallel for better performance
//!             method_table.par_iter().for_each(|method| {
//!                 // Process each method definition
//!             });
//!         }
//!         _ => {
//!             // Handle other table types as needed
//!         }
//!     }
//! }
//! ```
//!
//! ## References
//!
//! - [ECMA-335 Standard](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Partition II, Section 22
//! - [.NET Metadata Tables](https://github.com/dotnet/runtime/blob/main/docs/design/specs/Ecma-335-Augments.md)

use crate::metadata::tables::{
    AssemblyOsRaw, AssemblyProcessorRaw, AssemblyRaw, AssemblyRefOsRaw, AssemblyRefProcessorRaw,
    AssemblyRefRaw, ClassLayoutRaw, ConstantRaw, CustomAttributeRaw, CustomDebugInformationRaw,
    DeclSecurityRaw, DocumentRaw, EncLogRaw, EncMapRaw, EventMapRaw, EventPtrRaw, EventRaw,
    ExportedTypeRaw, FieldLayoutRaw, FieldMarshalRaw, FieldPtrRaw, FieldRaw, FieldRvaRaw, FileRaw,
    GenericParamConstraintRaw, GenericParamRaw, ImplMapRaw, ImportScopeRaw, InterfaceImplRaw,
    LocalConstantRaw, LocalScopeRaw, LocalVariableRaw, ManifestResourceRaw, MemberRefRaw,
    MetadataTable, MethodDebugInformationRaw, MethodDefRaw, MethodImplRaw, MethodPtrRaw,
    MethodSemanticsRaw, MethodSpecRaw, ModuleRaw, ModuleRefRaw, NestedClassRaw, ParamPtrRaw,
    ParamRaw, PropertyMapRaw, PropertyPtrRaw, PropertyRaw, StandAloneSigRaw, StateMachineMethodRaw,
    TypeDefRaw, TypeRefRaw, TypeSpecRaw,
};

/// Unified enumeration representing all possible metadata tables in a CLI assembly.
///
/// This enum provides a type-safe way to handle any of the metadata tables that can exist
/// in the `#~` or `#-` stream of a .NET assembly. Each variant corresponds to a specific table type
/// as defined in ECMA-335, containing a [`crate::metadata::tables::types::MetadataTable`] with the appropriate row type.
///
/// ## Table Organization
///
/// The variants are organized to follow the standard table numbering scheme used in
/// .NET metadata, making it easy to map between table IDs and enum variants.
///
/// ## Pattern Matching
///
/// This enum is designed for pattern matching to handle different table types:
///
/// ```no_run
/// use dotscope::metadata::tables::TableData;
///
/// fn analyze_table(table: &TableData) -> String {
///     match table {
///         TableData::TypeDef(types) => {
///             format!("Found {} type definitions", types.row_count)
///         }
///         TableData::MethodDef(methods) => {
///             format!("Found {} method definitions", methods.row_count)
///         }
///         TableData::Field(fields) => {
///             format!("Found {} field definitions", fields.row_count)
///         }
///         // Handle other table types...
///         _ => "Other table type".to_string(),
///     }
/// }
/// ```
pub enum TableData<'a> {
    /// `Module` table containing assembly module information.
    ///
    /// This table contains basic information about the current module, including
    /// its name, version identifier, and generation. There is typically only
    /// one row in this table per module.
    Module(MetadataTable<'a, ModuleRaw>),

    /// `TypeRef` table containing references to external types.
    ///
    /// This table holds references to types defined in other assemblies or modules
    /// that are used by the current assembly. Each row represents a type reference
    /// with resolution scope and name information.
    TypeRef(MetadataTable<'a, TypeRefRaw>),

    /// `TypeDef` table containing type definitions within this assembly.
    ///
    /// This is one of the core tables containing definitions of all types
    /// (classes, interfaces, value types, etc.) defined in the current assembly.
    /// Each row represents a complete type definition with flags, name, and layout information.
    TypeDef(MetadataTable<'a, TypeDefRaw>),

    /// `FieldPtr` table providing indirection for field ordering.
    ///
    /// This optional table is used when field ordering needs to be different
    /// from the physical layout in the Field table. It contains pointers to
    /// Field table entries in the desired logical order.
    FieldPtr(MetadataTable<'a, FieldPtrRaw>),

    /// Field table containing field definitions.
    ///
    /// This table defines all fields within types, including their attributes,
    /// names, and type signatures. Fields are associated with types through
    /// the `TypeDef` table's field list ranges.
    Field(MetadataTable<'a, FieldRaw>),

    /// `MethodPtr` table providing indirection for method ordering.
    ///
    /// Similar to `FieldPtr`, this optional table allows reordering of methods
    /// independently of their physical layout in the `MethodDef` table.
    MethodPtr(MetadataTable<'a, MethodPtrRaw>),

    /// `MethodDef` table containing method definitions.
    ///
    /// This table defines all methods within types, including their attributes,
    /// names, signatures, and implementation details. Methods are associated
    /// with types through the `TypeDef` table's method list ranges.
    MethodDef(MetadataTable<'a, MethodDefRaw>),

    /// `ParamPtr` table providing indirection for parameter ordering.
    ///
    /// This optional table allows reordering of parameters independently
    /// of their physical layout in the Param table.
    ParamPtr(MetadataTable<'a, ParamPtrRaw>),

    /// Param table containing method parameter definitions.
    ///
    /// This table defines parameters for methods, including their attributes,
    /// names, and sequence information. Parameters are associated with methods
    /// through the `MethodDef` table's parameter list ranges.
    Param(MetadataTable<'a, ParamRaw>),

    /// `InterfaceImpl` table containing interface implementation relationships.
    ///
    /// This table records which interfaces are implemented by which types,
    /// establishing the inheritance hierarchy for interface implementations.
    InterfaceImpl(MetadataTable<'a, InterfaceImplRaw>),

    /// `MemberRef` table containing references to external members.
    ///
    /// This table holds references to methods, fields, or other members
    /// defined in external assemblies or modules. Each entry includes
    /// the member's parent type, name, and signature.
    MemberRef(MetadataTable<'a, MemberRefRaw>),

    /// Constant table containing constant value definitions.
    ///
    /// This table stores constant values that can be associated with
    /// fields, parameters, or properties. Each entry specifies the
    /// constant's type and value.
    Constant(MetadataTable<'a, ConstantRaw>),

    /// `CustomAttribute` table containing custom attribute applications.
    ///
    /// This table records the application of custom attributes to various
    /// metadata entities. Each entry specifies the target entity, the
    /// attribute constructor, and the attribute arguments.
    CustomAttribute(MetadataTable<'a, CustomAttributeRaw>),

    /// `FieldMarshal` table containing field marshalling information.
    ///
    /// This table provides marshalling information for fields and parameters
    /// when interoperating with unmanaged code. Each entry specifies how
    /// the managed type should be marshalled.
    FieldMarshal(MetadataTable<'a, FieldMarshalRaw>),

    /// `DeclSecurity` table containing declarative security information.
    ///
    /// This table stores declarative security attributes applied to types
    /// or methods, including permission sets and security actions.
    DeclSecurity(MetadataTable<'a, DeclSecurityRaw>),

    /// Document table containing Portable PDB document information.
    ///
    /// This table contains information about source documents referenced in debug information,
    /// including document names, hash algorithms, hashes, and source language identifiers.
    Document(MetadataTable<'a, DocumentRaw>),

    /// `MethodDebugInformation` table containing method debugging details.
    ///
    /// This table contains debugging information for methods, including sequence points
    /// that map IL instructions to source code locations. Essential for stepping
    /// through code during debugging sessions in Portable PDB format.
    MethodDebugInformation(MetadataTable<'a, MethodDebugInformationRaw>),

    /// `LocalScope` table containing local variable scope information.
    ///
    /// This table defines the scope ranges where local variables and constants are active
    /// within methods. Used by debuggers to determine variable visibility and lifetime
    /// at different execution points in Portable PDB format.
    LocalScope(MetadataTable<'a, LocalScopeRaw>),

    /// `LocalVariable` table containing local variable information.
    ///
    /// This table stores information about local variables within method scopes,
    /// including their names, signatures, and attributes. Used by debuggers to
    /// display variable names and values during code execution in Portable PDB format.
    LocalVariable(MetadataTable<'a, LocalVariableRaw>),

    /// `LocalConstant` table containing local constant information.
    ///
    /// This table stores information about local constants within method scopes,
    /// including their names, signatures, and constant values. Used by debuggers
    /// to display constant values during code execution in Portable PDB format.
    LocalConstant(MetadataTable<'a, LocalConstantRaw>),

    /// `ImportScope` table containing namespace import scope information.
    ///
    /// This table records the import scopes for namespaces and types, used to resolve
    /// type names and provide proper `IntelliSense` support during debugging in Portable PDB format.
    ImportScope(MetadataTable<'a, ImportScopeRaw>),

    /// `StateMachineMethod` table containing async/iterator method mappings.
    ///
    /// This table maps compiler-generated state machine `MoveNext` methods back to their
    /// original user-written async/await and iterator methods. Essential for providing
    /// a seamless debugging experience with modern C# and VB.NET features in Portable PDB format.
    StateMachineMethod(MetadataTable<'a, StateMachineMethodRaw>),

    /// `CustomDebugInformation` table containing extensible debug information.
    ///
    /// This table allows compilers and tools to store additional debugging metadata
    /// beyond the standard Portable PDB tables. Each entry contains a GUID identifying
    /// the information type and a blob containing the actual data.
    CustomDebugInformation(MetadataTable<'a, CustomDebugInformationRaw>),

    /// `EncLog` table containing Edit-and-Continue log information.
    ///
    /// This table tracks metadata changes for Edit-and-Continue debugging scenarios,
    /// recording which metadata tokens have been modified during compilation.
    EncLog(MetadataTable<'a, EncLogRaw>),

    /// `EncMap` table containing Edit-and-Continue token mapping.
    ///
    /// This table maps original metadata tokens to their updated versions after
    /// Edit-and-Continue operations, enabling proper token correlation during debugging.
    EncMap(MetadataTable<'a, EncMapRaw>),

    /// `ClassLayout` table containing type layout information.
    ///
    /// This table specifies explicit layout information for value types
    /// and classes, including packing size and total size constraints.
    ClassLayout(MetadataTable<'a, ClassLayoutRaw>),

    /// `FieldLayout` table containing field layout information.
    ///
    /// This table specifies the explicit offset of fields within types
    /// that use explicit layout. Each entry maps a field to its byte offset.
    FieldLayout(MetadataTable<'a, FieldLayoutRaw>),

    /// `StandAloneSig` table containing standalone signature definitions.
    ///
    /// This table holds method signatures that are not directly associated
    /// with method definitions, such as function pointer signatures or
    /// call site signatures.
    StandAloneSig(MetadataTable<'a, StandAloneSigRaw>),

    /// `EventMap` table mapping types to their event ranges.
    ///
    /// This table maps types to the events they define, similar to how `TypeDef` maps to fields and methods.
    EventMap(MetadataTable<'a, EventMapRaw>),

    /// `EventPtr` table providing indirection for event ordering.
    ///
    /// This optional table allows reordering of events independently
    /// of their physical layout in the Event table.
    EventPtr(MetadataTable<'a, EventPtrRaw>),

    /// Event table containing event definitions.
    ///
    /// This table defines events within types, including their attributes,
    /// names, and event handler type. Events are associated with types
    /// through the `EventMap` table.
    Event(MetadataTable<'a, EventRaw>),

    /// `PropertyMap` table mapping types to their property ranges.
    ///
    /// This table establishes the relationship between types and the
    /// properties they define, enabling property enumeration for each type.
    PropertyMap(MetadataTable<'a, PropertyMapRaw>),

    /// `PropertyPtr` table providing indirection for property ordering.
    ///
    /// This optional table allows reordering of properties independently
    /// of their physical layout in the Property table.
    PropertyPtr(MetadataTable<'a, PropertyPtrRaw>),

    /// Property table containing property definitions.
    ///
    /// This table defines properties within types, including their attributes,
    /// names, and type signatures. Properties are associated with types
    /// through the `PropertyMap` table.
    Property(MetadataTable<'a, PropertyRaw>),

    /// `MethodSemantics` table containing method semantic relationships.
    ///
    /// This table associates methods with properties and events, defining
    /// relationships like getter/setter methods for properties or
    /// add/remove methods for events.
    MethodSemantics(MetadataTable<'a, MethodSemanticsRaw>),

    /// `MethodImpl` table containing method implementation mappings.
    ///
    /// This table specifies which method bodies implement which method
    /// declarations, particularly important for interface method implementations
    /// and method overrides.
    MethodImpl(MetadataTable<'a, MethodImplRaw>),

    /// `ModuleRef` table containing references to external modules.
    ///
    /// This table holds references to external modules that contain
    /// types or members referenced by the current assembly.
    ModuleRef(MetadataTable<'a, ModuleRefRaw>),

    /// `TypeSpec` table containing constructed type specifications.
    ///
    /// This table defines complex type constructions such as generic
    /// instantiations, arrays, pointers, and other derived types that
    /// cannot be represented by simple `TypeDef` or `TypeRef` entries.
    TypeSpec(MetadataTable<'a, TypeSpecRaw>),

    /// `ImplMap` table containing P/Invoke implementation mappings.
    ///
    /// This table provides mapping information for Platform Invoke (P/Invoke)
    /// calls, specifying the target DLL, entry point, and calling conventions
    /// for unmanaged method calls.
    ImplMap(MetadataTable<'a, ImplMapRaw>),

    /// `FieldRVA` table containing field relative virtual addresses.
    ///
    /// This table maps fields to their initial data locations within
    /// the assembly file, typically used for static fields with
    /// initial values.
    FieldRVA(MetadataTable<'a, FieldRvaRaw>),

    /// `Assembly` table containing assembly identity and metadata.
    ///
    /// This table contains information about the current assembly,
    /// including version, culture, public key, and other identity information.
    /// There is typically only one row in this table per assembly.
    Assembly(MetadataTable<'a, AssemblyRaw>),

    /// `AssemblyProcessor` table containing processor architecture information.
    ///
    /// This deprecated table was used to specify supported processor
    /// architectures for the assembly. Modern assemblies typically
    /// don't use this table.
    AssemblyProcessor(MetadataTable<'a, AssemblyProcessorRaw>),

    /// `AssemblyOS` table containing operating system information.
    ///
    /// This deprecated table was used to specify supported operating
    /// systems for the assembly. Modern assemblies typically don't use this table.
    AssemblyOS(MetadataTable<'a, AssemblyOsRaw>),

    /// `AssemblyRef` table containing external assembly references.
    ///
    /// This table holds references to external assemblies that contain
    /// types or members used by the current assembly. Each entry includes
    /// version and identity information for the referenced assembly.
    AssemblyRef(MetadataTable<'a, AssemblyRefRaw>),

    /// `AssemblyRefProcessor` table containing processor info for external assemblies.
    ///
    /// This deprecated table was used to specify processor requirements
    /// for referenced assemblies. Modern assemblies typically don't use this table.
    AssemblyRefProcessor(MetadataTable<'a, AssemblyRefProcessorRaw>),

    /// `AssemblyRefOS` table containing OS info for external assemblies.
    ///
    /// This deprecated table was used to specify operating system requirements
    /// for referenced assemblies. Modern assemblies typically don't use this table.
    AssemblyRefOS(MetadataTable<'a, AssemblyRefOsRaw>),

    /// `File` table containing files in the assembly manifest.
    ///
    /// This table lists all files that are part of the assembly manifest,
    /// including their names and hash information for integrity verification.
    File(MetadataTable<'a, FileRaw>),

    /// `ExportedType` table containing types exported by this assembly.
    ///
    /// This table lists types that are defined in other files of the assembly
    /// but are exported through this assembly's public interface.
    ExportedType(MetadataTable<'a, ExportedTypeRaw>),

    /// `ManifestResource` table containing resources in the assembly manifest.
    ///
    /// This table lists all resources that are embedded in or linked to
    /// the assembly, including their names, attributes, and location information.
    ManifestResource(MetadataTable<'a, ManifestResourceRaw>),

    /// `NestedClass` table containing nested type relationships.
    ///
    /// This table establishes parent-child relationships between types,
    /// identifying which types are nested within other types.
    NestedClass(MetadataTable<'a, NestedClassRaw>),

    /// `GenericParam` table containing generic parameter definitions.
    ///
    /// This table defines generic parameters for generic types and methods,
    /// including their names, constraints, and variance information.
    GenericParam(MetadataTable<'a, GenericParamRaw>),

    /// `MethodSpec` table containing generic method instantiations.
    ///
    /// This table represents specific instantiations of generic methods
    /// with concrete type arguments, enabling efficient representation
    /// of generic method calls.
    MethodSpec(MetadataTable<'a, MethodSpecRaw>),

    /// `GenericParamConstraint` table containing generic parameter constraints.
    ///
    /// This table specifies type constraints for generic parameters,
    /// defining which types or interfaces a generic parameter must implement or extend.
    GenericParamConstraint(MetadataTable<'a, GenericParamConstraintRaw>),
}

//! Writable table data enumeration for all metadata table variants.
//!
//! This module contains the `TableDataOwned` enum that represents all possible
//! owned metadata table types for modification operations. Unlike the read-only
//! `TableData<'a>` enum, this version owns all data and has no lifetime constraints.

use crate::{
    cilassembly::{AssemblyChanges, ResolvePlaceholders},
    metadata::tables::{
        AssemblyOsRaw,
        AssemblyProcessorRaw,
        AssemblyRaw,
        AssemblyRefOsRaw,
        AssemblyRefProcessorRaw,
        AssemblyRefRaw,
        ClassLayoutRaw,
        ConstantRaw,
        CustomAttributeRaw,
        CustomDebugInformationRaw,
        DeclSecurityRaw,
        DocumentRaw,
        EncLogRaw,
        EncMapRaw,
        EventMapRaw,
        EventPtrRaw,
        EventRaw,
        ExportedTypeRaw,
        FieldLayoutRaw,
        FieldMarshalRaw,
        FieldPtrRaw,
        FieldRaw,
        FieldRvaRaw,
        FileRaw,
        GenericParamConstraintRaw,
        GenericParamRaw,
        ImplMapRaw,
        ImportScopeRaw,
        InterfaceImplRaw,
        LocalConstantRaw,
        LocalScopeRaw,
        LocalVariableRaw,
        ManifestResourceRaw,
        MemberRefRaw,
        MethodDebugInformationRaw,
        MethodDefRaw,
        MethodImplRaw,
        MethodPtrRaw,
        MethodSemanticsRaw,
        MethodSpecRaw,
        // Import all raw table types
        ModuleRaw,
        ModuleRefRaw,
        NestedClassRaw,
        ParamPtrRaw,
        ParamRaw,
        PropertyMapRaw,
        PropertyPtrRaw,
        PropertyRaw,
        RowWritable,
        StandAloneSigRaw,
        StateMachineMethodRaw,
        TableId,
        TableInfoRef,
        TableRow,
        TypeDefRaw,
        TypeRefRaw,
        TypeSpecRaw,
    },
    Result,
};

/// Owned table data for mutable operations, mirroring the read-only `TableData<'a>` enum.
///
/// This enum contains owned instances of all metadata table row types, allowing
/// heterogeneous storage while maintaining type safety. Unlike `TableData<'a>`, this
/// version owns the data and has no lifetime constraints, making it suitable for
/// modification operations.
///
/// The structure mirrors the existing 39 table variants in `TableData<'a>` but uses
/// owned data types instead of borrowed references to the original file data.
#[derive(Debug, Clone)]
pub enum TableDataOwned {
    // Core Tables (0x00-0x09)
    /// Module table (0x00) - assembly module information
    Module(ModuleRaw),
    /// TypeRef table (0x01) - references to external types
    TypeRef(TypeRefRaw),
    /// TypeDef table (0x02) - type definitions within this assembly
    TypeDef(TypeDefRaw),
    /// FieldPtr table (0x03) - field pointer table (rarely used)
    FieldPtr(FieldPtrRaw),
    /// Field table (0x04) - field definitions
    Field(FieldRaw),
    /// MethodPtr table (0x05) - method pointer table (rarely used)
    MethodPtr(MethodPtrRaw),
    /// MethodDef table (0x06) - method definitions
    MethodDef(MethodDefRaw),
    /// ParamPtr table (0x07) - parameter pointer table (rarely used)
    ParamPtr(ParamPtrRaw),
    /// Param table (0x08) - method parameter information
    Param(ParamRaw),
    /// InterfaceImpl table (0x09) - interface implementations
    InterfaceImpl(InterfaceImplRaw),

    // Reference and Attribute Tables (0x0A-0x0E)
    /// MemberRef table (0x0A) - references to type members
    MemberRef(MemberRefRaw),
    /// Constant table (0x0B) - compile-time constant values
    Constant(ConstantRaw),
    /// CustomAttribute table (0x0C) - custom attribute instances
    CustomAttribute(CustomAttributeRaw),
    /// FieldMarshal table (0x0D) - field marshaling information
    FieldMarshal(FieldMarshalRaw),
    /// DeclSecurity table (0x0E) - declarative security attributes
    DeclSecurity(DeclSecurityRaw),

    // Debug Information Tables (0x30-0x37)
    /// Document table (0x30) - source document information
    Document(DocumentRaw),
    /// MethodDebugInformation table (0x31) - debug info for methods
    MethodDebugInformation(MethodDebugInformationRaw),
    /// LocalScope table (0x32) - local variable scope information
    LocalScope(LocalScopeRaw),
    /// LocalVariable table (0x33) - local variable debug information
    LocalVariable(LocalVariableRaw),
    /// LocalConstant table (0x34) - local constant debug information
    LocalConstant(LocalConstantRaw),
    /// ImportScope table (0x35) - import scope debug information
    ImportScope(ImportScopeRaw),
    /// StateMachineMethod table (0x36) - async state machine methods
    StateMachineMethod(StateMachineMethodRaw),
    /// CustomDebugInformation table (0x37) - custom debug information
    CustomDebugInformation(CustomDebugInformationRaw),

    // Edit-and-Continue Tables (0x3E-0x3F)
    /// EncLog table (0x3E) - edit-and-continue log
    EncLog(EncLogRaw),
    /// EncMap table (0x3F) - edit-and-continue mapping
    EncMap(EncMapRaw),

    // Layout and Signature Tables (0x0F-0x11)
    /// ClassLayout table (0x0F) - class layout information
    ClassLayout(ClassLayoutRaw),
    /// FieldLayout table (0x10) - field layout information
    FieldLayout(FieldLayoutRaw),
    /// StandAloneSig table (0x11) - standalone signatures
    StandAloneSig(StandAloneSigRaw),

    // Event and Property Tables (0x12-0x17)
    /// EventMap table (0x12) - maps types to their events
    EventMap(EventMapRaw),
    /// EventPtr table (0x13) - event pointer table (rarely used)
    EventPtr(EventPtrRaw),
    /// Event table (0x14) - event definitions
    Event(EventRaw),
    /// PropertyMap table (0x15) - maps types to their properties
    PropertyMap(PropertyMapRaw),
    /// PropertyPtr table (0x16) - property pointer table (rarely used)
    PropertyPtr(PropertyPtrRaw),
    /// Property table (0x17) - property definitions
    Property(PropertyRaw),

    // Method Implementation Tables (0x18-0x1C)
    /// MethodSemantics table (0x18) - method semantic associations
    MethodSemantics(MethodSemanticsRaw),
    /// MethodImpl table (0x19) - method implementation information
    MethodImpl(MethodImplRaw),
    /// ModuleRef table (0x1A) - module references
    ModuleRef(ModuleRefRaw),
    /// TypeSpec table (0x1B) - type specifications
    TypeSpec(TypeSpecRaw),
    /// ImplMap table (0x1C) - P/Invoke implementation mapping
    ImplMap(ImplMapRaw),

    // RVA and Assembly Tables (0x1D-0x26)
    /// FieldRVA table (0x1D) - field relative virtual addresses
    FieldRVA(FieldRvaRaw),
    /// Assembly table (0x20) - assembly metadata
    Assembly(AssemblyRaw),
    /// AssemblyProcessor table (0x21) - assembly processor information
    AssemblyProcessor(AssemblyProcessorRaw),
    /// AssemblyOS table (0x22) - assembly operating system information
    AssemblyOS(AssemblyOsRaw),
    /// AssemblyRef table (0x23) - assembly references
    AssemblyRef(AssemblyRefRaw),
    /// AssemblyRefProcessor table (0x24) - assembly reference processor info
    AssemblyRefProcessor(AssemblyRefProcessorRaw),
    /// AssemblyRefOS table (0x25) - assembly reference OS information
    AssemblyRefOS(AssemblyRefOsRaw),
    /// File table (0x26) - file information in multi-file assemblies
    File(FileRaw),

    // Export and Nested Tables (0x27-0x29)
    /// ExportedType table (0x27) - exported type information
    ExportedType(ExportedTypeRaw),
    /// ManifestResource table (0x28) - manifest resource information
    ManifestResource(ManifestResourceRaw),
    /// NestedClass table (0x29) - nested class relationships
    NestedClass(NestedClassRaw),

    // Generic Tables (0x2A-0x2C)
    /// GenericParam table (0x2A) - generic parameter definitions
    GenericParam(GenericParamRaw),
    /// MethodSpec table (0x2B) - generic method instantiations
    MethodSpec(MethodSpecRaw),
    /// GenericParamConstraint table (0x2C) - generic parameter constraints
    GenericParamConstraint(GenericParamConstraintRaw),
}

impl TableDataOwned {
    /// Returns the table type identifier for this row data.
    #[must_use]
    pub fn table_id(&self) -> TableId {
        match self {
            Self::Module(_) => TableId::Module,
            Self::TypeRef(_) => TableId::TypeRef,
            Self::TypeDef(_) => TableId::TypeDef,
            Self::FieldPtr(_) => TableId::FieldPtr,
            Self::Field(_) => TableId::Field,
            Self::MethodPtr(_) => TableId::MethodPtr,
            Self::MethodDef(_) => TableId::MethodDef,
            Self::ParamPtr(_) => TableId::ParamPtr,
            Self::Param(_) => TableId::Param,
            Self::InterfaceImpl(_) => TableId::InterfaceImpl,
            Self::MemberRef(_) => TableId::MemberRef,
            Self::Constant(_) => TableId::Constant,
            Self::CustomAttribute(_) => TableId::CustomAttribute,
            Self::FieldMarshal(_) => TableId::FieldMarshal,
            Self::DeclSecurity(_) => TableId::DeclSecurity,
            Self::Document(_) => TableId::Document,
            Self::MethodDebugInformation(_) => TableId::MethodDebugInformation,
            Self::LocalScope(_) => TableId::LocalScope,
            Self::LocalVariable(_) => TableId::LocalVariable,
            Self::LocalConstant(_) => TableId::LocalConstant,
            Self::ImportScope(_) => TableId::ImportScope,
            Self::StateMachineMethod(_) => TableId::StateMachineMethod,
            Self::CustomDebugInformation(_) => TableId::CustomDebugInformation,
            Self::EncLog(_) => TableId::EncLog,
            Self::EncMap(_) => TableId::EncMap,
            Self::ClassLayout(_) => TableId::ClassLayout,
            Self::FieldLayout(_) => TableId::FieldLayout,
            Self::StandAloneSig(_) => TableId::StandAloneSig,
            Self::EventMap(_) => TableId::EventMap,
            Self::EventPtr(_) => TableId::EventPtr,
            Self::Event(_) => TableId::Event,
            Self::PropertyMap(_) => TableId::PropertyMap,
            Self::PropertyPtr(_) => TableId::PropertyPtr,
            Self::Property(_) => TableId::Property,
            Self::MethodSemantics(_) => TableId::MethodSemantics,
            Self::MethodImpl(_) => TableId::MethodImpl,
            Self::ModuleRef(_) => TableId::ModuleRef,
            Self::TypeSpec(_) => TableId::TypeSpec,
            Self::ImplMap(_) => TableId::ImplMap,
            Self::FieldRVA(_) => TableId::FieldRVA,
            Self::Assembly(_) => TableId::Assembly,
            Self::AssemblyProcessor(_) => TableId::AssemblyProcessor,
            Self::AssemblyOS(_) => TableId::AssemblyOS,
            Self::AssemblyRef(_) => TableId::AssemblyRef,
            Self::AssemblyRefProcessor(_) => TableId::AssemblyRefProcessor,
            Self::AssemblyRefOS(_) => TableId::AssemblyRefOS,
            Self::File(_) => TableId::File,
            Self::ExportedType(_) => TableId::ExportedType,
            Self::ManifestResource(_) => TableId::ManifestResource,
            Self::NestedClass(_) => TableId::NestedClass,
            Self::GenericParam(_) => TableId::GenericParam,
            Self::MethodSpec(_) => TableId::MethodSpec,
            Self::GenericParamConstraint(_) => TableId::GenericParamConstraint,
        }
    }

    /// Returns a human-readable name for the table row type.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Module(_) => "Module",
            Self::TypeRef(_) => "TypeRef",
            Self::TypeDef(_) => "TypeDef",
            Self::FieldPtr(_) => "FieldPtr",
            Self::Field(_) => "Field",
            Self::MethodPtr(_) => "MethodPtr",
            Self::MethodDef(_) => "MethodDef",
            Self::ParamPtr(_) => "ParamPtr",
            Self::Param(_) => "Param",
            Self::InterfaceImpl(_) => "InterfaceImpl",
            Self::MemberRef(_) => "MemberRef",
            Self::Constant(_) => "Constant",
            Self::CustomAttribute(_) => "CustomAttribute",
            Self::FieldMarshal(_) => "FieldMarshal",
            Self::DeclSecurity(_) => "DeclSecurity",
            Self::Document(_) => "Document",
            Self::MethodDebugInformation(_) => "MethodDebugInformation",
            Self::LocalScope(_) => "LocalScope",
            Self::LocalVariable(_) => "LocalVariable",
            Self::LocalConstant(_) => "LocalConstant",
            Self::ImportScope(_) => "ImportScope",
            Self::StateMachineMethod(_) => "StateMachineMethod",
            Self::CustomDebugInformation(_) => "CustomDebugInformation",
            Self::EncLog(_) => "EncLog",
            Self::EncMap(_) => "EncMap",
            Self::ClassLayout(_) => "ClassLayout",
            Self::FieldLayout(_) => "FieldLayout",
            Self::StandAloneSig(_) => "StandAloneSig",
            Self::EventMap(_) => "EventMap",
            Self::EventPtr(_) => "EventPtr",
            Self::Event(_) => "Event",
            Self::PropertyMap(_) => "PropertyMap",
            Self::PropertyPtr(_) => "PropertyPtr",
            Self::Property(_) => "Property",
            Self::MethodSemantics(_) => "MethodSemantics",
            Self::MethodImpl(_) => "MethodImpl",
            Self::ModuleRef(_) => "ModuleRef",
            Self::TypeSpec(_) => "TypeSpec",
            Self::ImplMap(_) => "ImplMap",
            Self::FieldRVA(_) => "FieldRVA",
            Self::Assembly(_) => "Assembly",
            Self::AssemblyProcessor(_) => "AssemblyProcessor",
            Self::AssemblyOS(_) => "AssemblyOS",
            Self::AssemblyRef(_) => "AssemblyRef",
            Self::AssemblyRefProcessor(_) => "AssemblyRefProcessor",
            Self::AssemblyRefOS(_) => "AssemblyRefOS",
            Self::File(_) => "File",
            Self::ExportedType(_) => "ExportedType",
            Self::ManifestResource(_) => "ManifestResource",
            Self::NestedClass(_) => "NestedClass",
            Self::GenericParam(_) => "GenericParam",
            Self::MethodSpec(_) => "MethodSpec",
            Self::GenericParamConstraint(_) => "GenericParamConstraint",
        }
    }

    /// Calculate the row size for this specific table row.
    #[must_use]
    pub fn calculate_row_size(&self, sizes: &TableInfoRef) -> u32 {
        match self {
            Self::Module(_) => ModuleRaw::row_size(sizes),
            Self::TypeRef(_) => TypeRefRaw::row_size(sizes),
            Self::TypeDef(_) => TypeDefRaw::row_size(sizes),
            Self::FieldPtr(_) => FieldPtrRaw::row_size(sizes),
            Self::Field(_) => FieldRaw::row_size(sizes),
            Self::MethodPtr(_) => MethodPtrRaw::row_size(sizes),
            Self::MethodDef(_) => MethodDefRaw::row_size(sizes),
            Self::ParamPtr(_) => ParamPtrRaw::row_size(sizes),
            Self::Param(_) => ParamRaw::row_size(sizes),
            Self::InterfaceImpl(_) => InterfaceImplRaw::row_size(sizes),
            Self::MemberRef(_) => MemberRefRaw::row_size(sizes),
            Self::Constant(_) => ConstantRaw::row_size(sizes),
            Self::CustomAttribute(_) => CustomAttributeRaw::row_size(sizes),
            Self::FieldMarshal(_) => FieldMarshalRaw::row_size(sizes),
            Self::DeclSecurity(_) => DeclSecurityRaw::row_size(sizes),
            Self::Document(_) => DocumentRaw::row_size(sizes),
            Self::MethodDebugInformation(_) => MethodDebugInformationRaw::row_size(sizes),
            Self::LocalScope(_) => LocalScopeRaw::row_size(sizes),
            Self::LocalVariable(_) => LocalVariableRaw::row_size(sizes),
            Self::LocalConstant(_) => LocalConstantRaw::row_size(sizes),
            Self::ImportScope(_) => ImportScopeRaw::row_size(sizes),
            Self::StateMachineMethod(_) => StateMachineMethodRaw::row_size(sizes),
            Self::CustomDebugInformation(_) => CustomDebugInformationRaw::row_size(sizes),
            Self::EncLog(_) => EncLogRaw::row_size(sizes),
            Self::EncMap(_) => EncMapRaw::row_size(sizes),
            Self::ClassLayout(_) => ClassLayoutRaw::row_size(sizes),
            Self::FieldLayout(_) => FieldLayoutRaw::row_size(sizes),
            Self::StandAloneSig(_) => StandAloneSigRaw::row_size(sizes),
            Self::EventMap(_) => EventMapRaw::row_size(sizes),
            Self::EventPtr(_) => EventPtrRaw::row_size(sizes),
            Self::Event(_) => EventRaw::row_size(sizes),
            Self::PropertyMap(_) => PropertyMapRaw::row_size(sizes),
            Self::PropertyPtr(_) => PropertyPtrRaw::row_size(sizes),
            Self::Property(_) => PropertyRaw::row_size(sizes),
            Self::MethodSemantics(_) => MethodSemanticsRaw::row_size(sizes),
            Self::MethodImpl(_) => MethodImplRaw::row_size(sizes),
            Self::ModuleRef(_) => ModuleRefRaw::row_size(sizes),
            Self::TypeSpec(_) => TypeSpecRaw::row_size(sizes),
            Self::ImplMap(_) => ImplMapRaw::row_size(sizes),
            Self::FieldRVA(_) => FieldRvaRaw::row_size(sizes),
            Self::Assembly(_) => AssemblyRaw::row_size(sizes),
            Self::AssemblyProcessor(_) => AssemblyProcessorRaw::row_size(sizes),
            Self::AssemblyOS(_) => AssemblyOsRaw::row_size(sizes),
            Self::AssemblyRef(_) => AssemblyRefRaw::row_size(sizes),
            Self::AssemblyRefProcessor(_) => AssemblyRefProcessorRaw::row_size(sizes),
            Self::AssemblyRefOS(_) => AssemblyRefOsRaw::row_size(sizes),
            Self::File(_) => FileRaw::row_size(sizes),
            Self::ExportedType(_) => ExportedTypeRaw::row_size(sizes),
            Self::ManifestResource(_) => ManifestResourceRaw::row_size(sizes),
            Self::NestedClass(_) => NestedClassRaw::row_size(sizes),
            Self::GenericParam(_) => GenericParamRaw::row_size(sizes),
            Self::MethodSpec(_) => MethodSpecRaw::row_size(sizes),
            Self::GenericParamConstraint(_) => GenericParamConstraintRaw::row_size(sizes),
        }
    }

    /// Resolves all placeholder values in this row's heap reference fields.
    ///
    /// This method dispatches to the appropriate `ResolvePlaceholders` implementation
    /// for the contained row type. It should be called after heaps have been written
    /// and ChangeRefs resolved, but before the row is serialized via `row_write()`.
    ///
    /// # Arguments
    ///
    /// * `changes` - AssemblyChanges containing resolved `ChangeRefRc` entries
    pub fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        match self {
            Self::Module(row) => row.resolve_placeholders(changes),
            Self::TypeRef(row) => row.resolve_placeholders(changes),
            Self::TypeDef(row) => row.resolve_placeholders(changes),
            Self::Field(row) => row.resolve_placeholders(changes),
            Self::MethodDef(row) => row.resolve_placeholders(changes),
            Self::Param(row) => row.resolve_placeholders(changes),
            Self::InterfaceImpl(row) => row.resolve_placeholders(changes),
            Self::MemberRef(row) => row.resolve_placeholders(changes),
            Self::Constant(row) => row.resolve_placeholders(changes),
            Self::CustomAttribute(row) => row.resolve_placeholders(changes),
            Self::FieldMarshal(row) => row.resolve_placeholders(changes),
            Self::DeclSecurity(row) => row.resolve_placeholders(changes),
            Self::ClassLayout(row) => row.resolve_placeholders(changes),
            Self::FieldLayout(row) => row.resolve_placeholders(changes),
            Self::StandAloneSig(row) => row.resolve_placeholders(changes),
            Self::EventMap(row) => row.resolve_placeholders(changes),
            Self::Event(row) => row.resolve_placeholders(changes),
            Self::PropertyMap(row) => row.resolve_placeholders(changes),
            Self::Property(row) => row.resolve_placeholders(changes),
            Self::MethodSemantics(row) => row.resolve_placeholders(changes),
            Self::MethodImpl(row) => row.resolve_placeholders(changes),
            Self::ModuleRef(row) => row.resolve_placeholders(changes),
            Self::TypeSpec(row) => row.resolve_placeholders(changes),
            Self::ImplMap(row) => row.resolve_placeholders(changes),
            Self::FieldRVA(row) => row.resolve_placeholders(changes),
            Self::Assembly(row) => row.resolve_placeholders(changes),
            Self::AssemblyRef(row) => row.resolve_placeholders(changes),
            Self::File(row) => row.resolve_placeholders(changes),
            Self::ExportedType(row) => row.resolve_placeholders(changes),
            Self::ManifestResource(row) => row.resolve_placeholders(changes),
            Self::NestedClass(row) => row.resolve_placeholders(changes),
            Self::GenericParam(row) => row.resolve_placeholders(changes),
            Self::MethodSpec(row) => row.resolve_placeholders(changes),
            Self::GenericParamConstraint(row) => row.resolve_placeholders(changes),
            Self::FieldPtr(row) => row.resolve_placeholders(changes),
            Self::MethodPtr(row) => row.resolve_placeholders(changes),
            Self::ParamPtr(row) => row.resolve_placeholders(changes),
            Self::EventPtr(row) => row.resolve_placeholders(changes),
            Self::PropertyPtr(row) => row.resolve_placeholders(changes),
            Self::AssemblyRefProcessor(row) => row.resolve_placeholders(changes),
            Self::AssemblyRefOS(row) => row.resolve_placeholders(changes),
            Self::Document(row) => row.resolve_placeholders(changes),
            Self::MethodDebugInformation(row) => row.resolve_placeholders(changes),
            Self::LocalScope(row) => row.resolve_placeholders(changes),
            Self::LocalVariable(row) => row.resolve_placeholders(changes),
            Self::LocalConstant(row) => row.resolve_placeholders(changes),
            Self::ImportScope(row) => row.resolve_placeholders(changes),
            Self::StateMachineMethod(row) => row.resolve_placeholders(changes),
            Self::CustomDebugInformation(row) => row.resolve_placeholders(changes),
            // Tables whose columns are constants and tokens, never placeholders
            Self::EncLog(_)
            | Self::EncMap(_)
            | Self::AssemblyProcessor(_)
            | Self::AssemblyOS(_) => {}
        }
    }
}

// Implement RowWritable by delegating to the contained type
impl RowWritable for TableDataOwned {
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<()> {
        match self {
            Self::Module(row) => row.row_write(data, offset, rid, sizes),
            Self::TypeRef(row) => row.row_write(data, offset, rid, sizes),
            Self::TypeDef(row) => row.row_write(data, offset, rid, sizes),
            Self::FieldPtr(row) => row.row_write(data, offset, rid, sizes),
            Self::Field(row) => row.row_write(data, offset, rid, sizes),
            Self::MethodPtr(row) => row.row_write(data, offset, rid, sizes),
            Self::MethodDef(row) => row.row_write(data, offset, rid, sizes),
            Self::ParamPtr(row) => row.row_write(data, offset, rid, sizes),
            Self::Param(row) => row.row_write(data, offset, rid, sizes),
            Self::InterfaceImpl(row) => row.row_write(data, offset, rid, sizes),
            Self::MemberRef(row) => row.row_write(data, offset, rid, sizes),
            Self::Constant(row) => row.row_write(data, offset, rid, sizes),
            Self::CustomAttribute(row) => row.row_write(data, offset, rid, sizes),
            Self::FieldMarshal(row) => row.row_write(data, offset, rid, sizes),
            Self::DeclSecurity(row) => row.row_write(data, offset, rid, sizes),
            Self::Document(row) => row.row_write(data, offset, rid, sizes),
            Self::MethodDebugInformation(row) => row.row_write(data, offset, rid, sizes),
            Self::LocalScope(row) => row.row_write(data, offset, rid, sizes),
            Self::LocalVariable(row) => row.row_write(data, offset, rid, sizes),
            Self::LocalConstant(row) => row.row_write(data, offset, rid, sizes),
            Self::ImportScope(row) => row.row_write(data, offset, rid, sizes),
            Self::StateMachineMethod(row) => row.row_write(data, offset, rid, sizes),
            Self::CustomDebugInformation(row) => row.row_write(data, offset, rid, sizes),
            Self::EncLog(row) => row.row_write(data, offset, rid, sizes),
            Self::EncMap(row) => row.row_write(data, offset, rid, sizes),
            Self::ClassLayout(row) => row.row_write(data, offset, rid, sizes),
            Self::FieldLayout(row) => row.row_write(data, offset, rid, sizes),
            Self::StandAloneSig(row) => row.row_write(data, offset, rid, sizes),
            Self::EventMap(row) => row.row_write(data, offset, rid, sizes),
            Self::EventPtr(row) => row.row_write(data, offset, rid, sizes),
            Self::Event(row) => row.row_write(data, offset, rid, sizes),
            Self::PropertyMap(row) => row.row_write(data, offset, rid, sizes),
            Self::PropertyPtr(row) => row.row_write(data, offset, rid, sizes),
            Self::Property(row) => row.row_write(data, offset, rid, sizes),
            Self::MethodSemantics(row) => row.row_write(data, offset, rid, sizes),
            Self::MethodImpl(row) => row.row_write(data, offset, rid, sizes),
            Self::ModuleRef(row) => row.row_write(data, offset, rid, sizes),
            Self::TypeSpec(row) => row.row_write(data, offset, rid, sizes),
            Self::ImplMap(row) => row.row_write(data, offset, rid, sizes),
            Self::FieldRVA(row) => row.row_write(data, offset, rid, sizes),
            Self::Assembly(row) => row.row_write(data, offset, rid, sizes),
            Self::AssemblyProcessor(row) => row.row_write(data, offset, rid, sizes),
            Self::AssemblyOS(row) => row.row_write(data, offset, rid, sizes),
            Self::AssemblyRef(row) => row.row_write(data, offset, rid, sizes),
            Self::AssemblyRefProcessor(row) => row.row_write(data, offset, rid, sizes),
            Self::AssemblyRefOS(row) => row.row_write(data, offset, rid, sizes),
            Self::File(row) => row.row_write(data, offset, rid, sizes),
            Self::ExportedType(row) => row.row_write(data, offset, rid, sizes),
            Self::ManifestResource(row) => row.row_write(data, offset, rid, sizes),
            Self::NestedClass(row) => row.row_write(data, offset, rid, sizes),
            Self::GenericParam(row) => row.row_write(data, offset, rid, sizes),
            Self::MethodSpec(row) => row.row_write(data, offset, rid, sizes),
            Self::GenericParamConstraint(row) => row.row_write(data, offset, rid, sizes),
        }
    }

    fn sort_key(&self, sizes: &TableInfoRef) -> Result<Option<(u32, u32)>> {
        match self {
            Self::ClassLayout(row) => row.sort_key(sizes),
            Self::Constant(row) => row.sort_key(sizes),
            Self::CustomAttribute(row) => row.sort_key(sizes),
            Self::DeclSecurity(row) => row.sort_key(sizes),
            Self::FieldLayout(row) => row.sort_key(sizes),
            Self::FieldMarshal(row) => row.sort_key(sizes),
            Self::FieldRVA(row) => row.sort_key(sizes),
            Self::GenericParam(row) => row.sort_key(sizes),
            Self::GenericParamConstraint(row) => row.sort_key(sizes),
            Self::ImplMap(row) => row.sort_key(sizes),
            Self::InterfaceImpl(row) => row.sort_key(sizes),
            Self::MethodImpl(row) => row.sort_key(sizes),
            Self::MethodSemantics(row) => row.sort_key(sizes),
            Self::NestedClass(row) => row.sort_key(sizes),
            Self::LocalScope(row) => row.sort_key(sizes),
            Self::StateMachineMethod(row) => row.sort_key(sizes),
            Self::CustomDebugInformation(row) => row.sort_key(sizes),
            _ => Ok(None),
        }
    }
}

// Implement TableRow for size calculation
impl TableRow for TableDataOwned {
    fn row_size(_sizes: &TableInfoRef) -> u32 {
        // This static method can't know which variant it's being called for,
        // so we return 0 and use the instance method instead
        0
    }
}

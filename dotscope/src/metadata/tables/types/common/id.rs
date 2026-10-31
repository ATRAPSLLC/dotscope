use std::fmt;

use strum::{EnumCount, EnumIter};

/// Identifiers for the different metadata tables defined in the ECMA-335 specification.
///
/// Each variant represents a specific type of metadata table that can be present in a .NET assembly.
/// The numeric values correspond to the table IDs as defined in the CLI specification.
///
/// ## Table Categories
///
/// ### Core Type System
/// - **`Module`**: Assembly module information
/// - **`TypeDef`**: Type definitions (classes, interfaces, enums, etc.)
/// - **`TypeRef`**: Type references to external assemblies
/// - **`Field`**: Field definitions within types
/// - **`MethodDef`**: Method definitions
/// - **`Param`**: Method parameter definitions
///
/// ### Indirection Tables (`#-` Streams)
/// - **`FieldPtr`**: Indirection table for Field entries in uncompressed streams
/// - **`MethodPtr`**: Indirection table for `MethodDef` entries in uncompressed streams
/// - **`ParamPtr`**: Indirection table for Param entries in uncompressed streams
/// - **`EventPtr`**: Indirection table for Event entries in uncompressed streams
/// - **`PropertyPtr`**: Indirection table for Property entries in uncompressed streams
///
/// ### Type Relationships
/// - **`InterfaceImpl`**: Interface implementations by types
/// - **`NestedClass`**: Nested class relationships
/// - **`ClassLayout`**: Memory layout information for types
/// - **`FieldLayout`**: Field layout within types
///
/// ### Member References
/// - **`MemberRef`**: References to external members (methods, fields)
/// - **`MethodImpl`**: Method implementation mappings
/// - **`MethodSemantics`**: Property/event accessor mappings
///
/// ### Metadata and Attributes
/// - **`CustomAttribute`**: Custom attribute applications
/// - **`Constant`**: Compile-time constant values
/// - **`FieldMarshal`**: P/Invoke marshalling information
/// - **`DeclSecurity`**: Declarative security permissions
///
/// ### Signatures and Specifications
/// - **`StandAloneSig`**: Standalone method signatures
/// - **`TypeSpec`**: Generic type specifications
/// - **`MethodSpec`**: Generic method specifications
/// - **`GenericParam`**: Generic parameter definitions
/// - **`GenericParamConstraint`**: Generic parameter constraints
///
/// ### Events and Properties
/// - **`Event`**: Event definitions
/// - **`EventMap`**: Type-to-event mappings
/// - **`Property`**: Property definitions  
/// - **`PropertyMap`**: Type-to-property mappings
///
/// ### Assembly Information
/// - **`Assembly`**: Current assembly metadata
/// - **`AssemblyRef`**: External assembly references
/// - **`AssemblyProcessor`**: Processor-specific assembly info
/// - **`AssemblyOS`**: OS-specific assembly info
/// - **`AssemblyRefProcessor`**: External assembly processor info
/// - **`AssemblyRefOS`**: External assembly OS info
///
/// ### Files and Resources
/// - **`File`**: File references in the assembly
/// - **`ExportedType`**: Types exported from this assembly
/// - **`ManifestResource`**: Embedded or linked resources
///
/// ### Platform Interop
/// - **`ImplMap`**: P/Invoke implementation mappings
/// - **`FieldRVA`**: Field relative virtual addresses for initialized data
/// - **`ModuleRef`**: External module references
///
/// ## Reference
/// * [ECMA-335 Partition II, Section 22](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Metadata Tables
#[derive(Clone, Copy, PartialEq, Debug, EnumIter, EnumCount, Eq, Hash)]
pub enum TableId {
    /// `Module` table (0x00) - Contains information about the current module/assembly.
    ///
    /// Each assembly has exactly one Module row that describes the module itself,
    /// including its name, MVID (Module Version ID), and generation information.
    Module = 0x00,

    /// `TypeRef` table (0x01) - References to types defined in external assemblies.
    ///
    /// Contains references to types that are imported from other assemblies,
    /// including the type name, namespace, and resolution scope.
    TypeRef = 0x01,

    /// `TypeDef` table (0x02) - Definitions of types within this assembly.
    ///
    /// Contains all type definitions (classes, interfaces, enums, delegates, etc.)
    /// defined within this assembly, including their flags, name, namespace,
    /// base type, and member lists.
    TypeDef = 0x02,

    /// `FieldPtr` table (0x03) - Indirection table for Field entries in `#-` streams.
    ///
    /// This table is only present in assemblies using uncompressed metadata streams (`#-`).
    /// Each row contains a single field: a 1-based index into the Field table.
    /// When present, field references should resolve through this indirection table.
    FieldPtr = 0x03,

    /// `Field` table (0x04) - Field definitions within types.
    ///
    /// Contains all field definitions, including their attributes, name,
    /// and signature. Fields are owned by types defined in the `TypeDef` table.
    Field = 0x04,

    /// `MethodPtr` table (0x05) - Indirection table for `MethodDef` entries in `#-` streams.
    ///
    /// This table is only present in assemblies using uncompressed metadata streams (`#-`).
    /// Each row contains a single field: a 1-based index into the `MethodDef` table.
    /// When present, method references should resolve through this indirection table.
    MethodPtr = 0x05,

    /// `MethodDef` table (0x06) - Method definitions within types.
    ///
    /// Contains all method definitions including constructors, instance methods,
    /// static methods, and finalizers. Includes method attributes, name,
    /// signature, and RVA (if the method has IL code).
    MethodDef = 0x06,

    /// `ParamPtr` table (0x07) - Indirection table for Param entries in `#-` streams.
    ///
    /// This table is only present in assemblies using uncompressed metadata streams (`#-`).
    /// Each row contains a single field: a 1-based index into the Param table.
    /// When present, parameter references should resolve through this indirection table.
    ParamPtr = 0x07,

    /// `Param` table (0x08) - Parameter definitions for methods.
    ///
    /// Contains parameter information for methods, including parameter attributes,
    /// sequence number, and name. Each parameter belongs to a method in `MethodDef`.
    Param = 0x08,

    /// `InterfaceImpl` table (0x09) - Interface implementations by types.
    ///
    /// Records which interfaces are implemented by which types. Each row
    /// represents a type implementing a specific interface.
    InterfaceImpl = 0x09,

    /// `MemberRef` table (0x0A) - References to external members.
    ///
    /// Contains references to methods and fields that are defined in external
    /// assemblies or modules, including the member name and signature.
    MemberRef = 0x0A,

    /// `Constant` table (0x0B) - Compile-time constant values.
    ///
    /// Contains constant values for fields, parameters, and properties.
    /// Includes the constant type and value data.
    Constant = 0x0B,

    /// `CustomAttribute` table (0x0C) - Custom attribute applications.
    ///
    /// Records the application of custom attributes to various metadata elements
    /// such as types, methods, fields, assemblies, etc. Contains the attribute
    /// constructor and value blob.
    CustomAttribute = 0x0C,

    /// `FieldMarshal` table (0x0D) - P/Invoke marshalling information for fields.
    ///
    /// Contains marshalling information for fields that require special
    /// handling during P/Invoke calls, such as string marshalling or
    /// struct layout specifications.
    FieldMarshal = 0x0D,

    /// `DeclSecurity` table (0x0E) - Declarative security permissions.
    ///
    /// Contains declarative security attributes applied to types and methods,
    /// specifying required permissions, demanded permissions, and other
    /// security-related metadata.
    DeclSecurity = 0x0E,

    /// `ClassLayout` table (0x0F) - Memory layout information for types.
    ///
    /// Specifies explicit layout information for types, including packing size
    /// and class size. Used for types that require specific memory layouts
    /// for interop scenarios.
    ClassLayout = 0x0F,

    /// `FieldLayout` table (0x10) - Explicit field positioning within types.
    ///
    /// Contains explicit offset information for fields in types with
    /// explicit layout. Each row specifies the byte offset of a field
    /// within its containing type.
    FieldLayout = 0x10,

    /// `StandAloneSig` table (0x11) - Standalone method signatures.
    ///
    /// Contains method signatures that are not directly associated with
    /// a method definition, such as signatures for function pointers
    /// or unmanaged calling conventions.
    StandAloneSig = 0x11,

    /// `EventMap` table (0x12) - Mapping from types to their events.
    ///
    /// Establishes the relationship between types and the events they define.
    /// Each row maps a type to a range of events in the Event table.
    EventMap = 0x12,

    /// `EventPtr` table (0x13) - Indirection table for Event entries in `#-` streams.
    ///
    /// This table is only present in assemblies using uncompressed metadata streams (`#-`).
    /// Each row contains a single field: a 1-based index into the Event table.
    /// When present, event references should resolve through this indirection table.
    EventPtr = 0x13,

    /// `Event` table (0x14) - Event definitions within types.
    ///
    /// Contains event definitions, including event attributes, name, and
    /// event type. Events are used for the publisher-subscriber pattern
    /// in .NET programming.
    Event = 0x14,

    /// `PropertyMap` table (0x15) - Mapping from types to their properties.
    ///
    /// Establishes the relationship between types and the properties they define.
    /// Each row maps a type to a range of properties in the Property table.
    PropertyMap = 0x15,

    /// `PropertyPtr` table (0x16) - Indirection table for Property entries in `#-` streams.
    ///
    /// This table is only present in assemblies using uncompressed metadata streams (`#-`).
    /// Each row contains a single field: a 1-based index into the Property table.
    /// When present, property references should resolve through this indirection table.
    PropertyPtr = 0x16,

    /// `Property` table (0x17) - Property definitions within types.
    ///
    /// Contains property definitions, including property attributes, name,
    /// and property signature. Properties provide controlled access to
    /// type members through getter and setter methods.
    Property = 0x17,

    /// `MethodSemantics` table (0x18) - Property and event accessor mappings.
    ///
    /// Associates methods with properties and events, specifying whether
    /// a method is a getter, setter, adder, remover, or fire method.
    MethodSemantics = 0x18,

    /// `MethodImpl` table (0x19) - Method implementation mappings.
    ///
    /// Specifies which method implementations correspond to interface
    /// method declarations. Used for explicit interface implementations
    /// and method overrides.
    MethodImpl = 0x19,

    /// `ModuleRef` table (0x1A) - References to external modules.
    ///
    /// Contains references to external modules (DLLs) that are used
    /// by this assembly, primarily for P/Invoke scenarios.
    ModuleRef = 0x1A,

    /// `TypeSpec` table (0x1B) - Generic type specifications.
    ///
    /// Contains instantiated generic types and other complex type
    /// specifications that cannot be represented by simple `TypeRef`
    /// or `TypeDef` entries.
    TypeSpec = 0x1B,

    /// `ImplMap` table (0x1C) - P/Invoke implementation mappings.
    ///
    /// Contains P/Invoke mapping information for methods that call
    /// unmanaged code, including the target DLL and entry point name.
    ImplMap = 0x1C,

    /// `FieldRVA` table (0x1D) - Field relative virtual addresses.
    ///
    /// Contains RVA (Relative Virtual Address) information for fields
    /// that have initial data, such as static fields with initializers
    /// or mapped data fields.
    FieldRVA = 0x1D,

    /// `EncLog` table (0x1E) - Edit-and-Continue log entries.
    ///
    /// Records all edit operations performed during debugging sessions that use
    /// Edit-and-Continue functionality. Each entry specifies a metadata token
    /// and the type of operation (create, update, delete) performed on that element.
    EncLog = 0x1E,

    /// `EncMap` table (0x1F) - Edit-and-Continue token mapping.
    ///
    /// Maps original metadata tokens to their updated versions after Edit-and-Continue
    /// operations. This table enables debuggers to correlate pre-edit and post-edit
    /// metadata tokens, maintaining proper references during debugging sessions.
    EncMap = 0x1F,

    /// `Assembly` table (0x20) - Current assembly metadata.
    ///
    /// Contains metadata about the current assembly, including version
    /// information, security permissions, and assembly attributes.
    /// Each assembly has exactly one Assembly row.
    Assembly = 0x20,

    /// `AssemblyProcessor` table (0x21) - Processor-specific assembly information.
    ///
    /// Contains processor architecture information for the assembly,
    /// though this table is rarely used in practice.
    AssemblyProcessor = 0x21,

    /// `AssemblyOS` table (0x22) - Operating system-specific assembly information.
    ///
    /// Contains operating system information for the assembly,
    /// though this table is rarely used in practice.
    AssemblyOS = 0x22,

    /// `AssemblyRef` table (0x23) - References to external assemblies.
    ///
    /// Contains references to other assemblies that this assembly depends on,
    /// including version information and public key tokens.
    AssemblyRef = 0x23,

    /// `AssemblyRefProcessor` table (0x24) - Processor info for external assemblies.
    ///
    /// Contains processor architecture information for referenced assemblies,
    /// though this table is rarely used in practice.
    AssemblyRefProcessor = 0x24,

    /// `AssemblyRefOS` table (0x25) - OS info for external assemblies.
    ///
    /// Contains operating system information for referenced assemblies,
    /// though this table is rarely used in practice.
    AssemblyRefOS = 0x25,

    /// `File` table (0x26) - File references within the assembly.
    ///
    /// Contains references to files that are part of the assembly,
    /// such as modules and resources that are stored in separate files.
    File = 0x26,

    /// `ExportedType` table (0x27) - Types exported from this assembly.
    ///
    /// Contains information about types that are defined in this assembly
    /// but forwarded from other assemblies, enabling type forwarding scenarios.
    ExportedType = 0x27,

    /// `ManifestResource` table (0x28) - Assembly resources.
    ///
    /// Contains information about resources embedded in or linked to the assembly,
    /// including resource names, attributes, and location information.
    ManifestResource = 0x28,

    /// `NestedClass` table (0x29) - Nested class relationships.
    ///
    /// Establishes parent-child relationships between types, indicating
    /// which types are nested within other types.
    NestedClass = 0x29,

    /// `GenericParam` table (0x2A) - Generic parameter definitions.
    ///
    /// Contains generic parameter information for generic types and methods,
    /// including parameter names, constraints, and variance information.
    GenericParam = 0x2A,

    /// `MethodSpec` table (0x2B) - Generic method specifications.
    ///
    /// Contains instantiated generic methods with specific type arguments,
    /// allowing references to generic methods with concrete type parameters.
    MethodSpec = 0x2B,

    /// `GenericParamConstraint` table (0x2C) - Generic parameter constraints.
    ///
    /// Specifies constraints on generic parameters, such as base class
    /// constraints, interface constraints, and special constraints
    /// (`new()`, class, struct).
    GenericParamConstraint = 0x2C,

    /// `Document` table (0x30) - Portable PDB document information.
    ///
    /// Contains information about source documents referenced in debug information,
    /// including document names, languages, hash algorithms, and source text.
    /// Part of the Portable PDB format for enhanced debugging support.
    Document = 0x30,

    /// `MethodDebugInformation` table (0x31) - Method debugging details.
    ///
    /// Contains debugging information for methods, including sequence points
    /// that map IL instructions to source code locations. Essential for
    /// stepping through code during debugging sessions.
    MethodDebugInformation = 0x31,

    /// `LocalScope` table (0x32) - Local variable scope information.
    ///
    /// Defines the scope ranges where local variables and constants are active
    /// within methods. Used by debuggers to determine variable visibility
    /// and lifetime at different execution points.
    LocalScope = 0x32,

    /// `LocalVariable` table (0x33) - Local variable debug information.
    ///
    /// Contains debugging information for local variables, including their
    /// names, signatures, and attributes. Enables debuggers to display
    /// meaningful variable information during debugging.
    LocalVariable = 0x33,

    /// `LocalConstant` table (0x34) - Local constant debug information.
    ///
    /// Contains debugging information for local constants, including their
    /// names, signatures, and compile-time values. Allows debuggers to
    /// display constant values during debugging sessions.
    LocalConstant = 0x34,

    /// `ImportScope` table (0x35) - Namespace import scope information.
    ///
    /// Defines the scope ranges where namespace imports (`using` statements
    /// in C#) are active. Enables debuggers to resolve type names and
    /// provide proper `IntelliSense` support during debugging.
    ImportScope = 0x35,

    /// `StateMachineMethod` table (0x36) - Async/iterator state machine info.
    ///
    /// Links state machine methods (generated for async/await and iterators)
    /// back to their original user-written methods. Critical for providing
    /// a seamless debugging experience with async and iterator methods.
    StateMachineMethod = 0x36,

    /// `CustomDebugInformation` table (0x37) - Custom debugging metadata.
    ///
    /// Contains custom debugging information that can be defined by compilers
    /// or tools. Provides extensibility for debugging scenarios beyond the
    /// standard Portable PDB tables.
    CustomDebugInformation = 0x37,
}

impl fmt::Display for TableId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl TableId {
    /// Returns the token type value for this table ID.
    ///
    /// The token type is the high byte (bits 24-31) of metadata tokens that reference
    /// rows in this table. This value is used to construct token values and extract
    /// table information from existing tokens.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::tables::TableId;
    ///
    /// assert_eq!(TableId::Module.token_type(), 0x00);
    /// assert_eq!(TableId::TypeRef.token_type(), 0x01);
    /// assert_eq!(TableId::TypeDef.token_type(), 0x02);
    /// ```
    #[must_use]
    pub fn token_type(&self) -> u8 {
        *self as u8
    }

    /// Creates a TableId from a token type value.
    ///
    /// Converts the high byte (bits 24-31) of a metadata token back to the
    /// corresponding TableId. Returns `None` if the token type doesn't correspond
    /// to a valid table ID.
    ///
    /// # Arguments
    ///
    /// * `token_type` - The token type value (0x00-0x37)
    ///
    /// # Returns
    ///
    /// Returns `Some(TableId)` if the token type is valid, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::tables::TableId;
    ///
    /// assert_eq!(TableId::from_token_type(0x00), Some(TableId::Module));
    /// assert_eq!(TableId::from_token_type(0x01), Some(TableId::TypeRef));
    /// assert_eq!(TableId::from_token_type(0x02), Some(TableId::TypeDef));
    /// assert_eq!(TableId::from_token_type(0xFF), None);
    /// ```
    #[must_use]
    pub fn from_token_type(token_type: u8) -> Option<Self> {
        match token_type {
            0x00 => Some(TableId::Module),
            0x01 => Some(TableId::TypeRef),
            0x02 => Some(TableId::TypeDef),
            0x03 => Some(TableId::FieldPtr),
            0x04 => Some(TableId::Field),
            0x05 => Some(TableId::MethodPtr),
            0x06 => Some(TableId::MethodDef),
            0x07 => Some(TableId::ParamPtr),
            0x08 => Some(TableId::Param),
            0x09 => Some(TableId::InterfaceImpl),
            0x0A => Some(TableId::MemberRef),
            0x0B => Some(TableId::Constant),
            0x0C => Some(TableId::CustomAttribute),
            0x0D => Some(TableId::FieldMarshal),
            0x0E => Some(TableId::DeclSecurity),
            0x0F => Some(TableId::ClassLayout),
            0x10 => Some(TableId::FieldLayout),
            0x11 => Some(TableId::StandAloneSig),
            0x12 => Some(TableId::EventMap),
            0x13 => Some(TableId::EventPtr),
            0x14 => Some(TableId::Event),
            0x15 => Some(TableId::PropertyMap),
            0x16 => Some(TableId::PropertyPtr),
            0x17 => Some(TableId::Property),
            0x18 => Some(TableId::MethodSemantics),
            0x19 => Some(TableId::MethodImpl),
            0x1A => Some(TableId::ModuleRef),
            0x1B => Some(TableId::TypeSpec),
            0x1C => Some(TableId::ImplMap),
            0x1D => Some(TableId::FieldRVA),
            0x1E => Some(TableId::EncLog),
            0x1F => Some(TableId::EncMap),
            0x20 => Some(TableId::Assembly),
            0x21 => Some(TableId::AssemblyProcessor),
            0x22 => Some(TableId::AssemblyOS),
            0x23 => Some(TableId::AssemblyRef),
            0x24 => Some(TableId::AssemblyRefProcessor),
            0x25 => Some(TableId::AssemblyRefOS),
            0x26 => Some(TableId::File),
            0x27 => Some(TableId::ExportedType),
            0x28 => Some(TableId::ManifestResource),
            0x29 => Some(TableId::NestedClass),
            0x2A => Some(TableId::GenericParam),
            0x2B => Some(TableId::MethodSpec),
            0x2C => Some(TableId::GenericParamConstraint),
            0x30 => Some(TableId::Document),
            0x31 => Some(TableId::MethodDebugInformation),
            0x32 => Some(TableId::LocalScope),
            0x33 => Some(TableId::LocalVariable),
            0x34 => Some(TableId::LocalConstant),
            0x35 => Some(TableId::ImportScope),
            0x36 => Some(TableId::StateMachineMethod),
            0x37 => Some(TableId::CustomDebugInformation),
            _ => None,
        }
    }

    /// Returns true if this table type has cross-table references that would
    /// need remapping when other tables have row deletions.
    ///
    /// Tables with cross-table references contain fields that point to rows
    /// in other tables (either directly via RID or through coded indices).
    /// When rows are deleted from referenced tables, these references must
    /// be updated to maintain metadata integrity.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::tables::TableId;
    ///
    /// // TypeDef references Field and MethodDef tables
    /// assert!(TableId::TypeDef.has_cross_references());
    ///
    /// // Module table has no cross-table references
    /// assert!(!TableId::Module.has_cross_references());
    /// ```
    #[must_use]
    pub fn has_cross_references(&self) -> bool {
        !self.references().is_empty()
    }

    /// Returns the set of tables that this table references.
    ///
    /// This identifies which tables a given table has dependencies on through
    /// its fields. Used to determine if a table needs remapping based on which
    /// tables have deletions - if any of the returned tables have deletions,
    /// this table's rows may need their references updated.
    ///
    /// # Returns
    ///
    /// A static slice of `TableId` values representing all tables that this
    /// table can reference. Returns an empty slice for tables without
    /// cross-table references.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::tables::TableId;
    ///
    /// // TypeDef references TypeDef, TypeRef, TypeSpec (extends), Field, and MethodDef
    /// let refs = TableId::TypeDef.references();
    /// assert!(refs.contains(&TableId::Field));
    /// assert!(refs.contains(&TableId::MethodDef));
    ///
    /// // Module has no references
    /// assert!(TableId::Module.references().is_empty());
    /// ```
    #[must_use]
    pub fn references(&self) -> &'static [TableId] {
        match self {
            TableId::TypeRef => &[
                TableId::Module,
                TableId::ModuleRef,
                TableId::AssemblyRef,
                TableId::TypeRef,
            ],
            TableId::TypeDef => &[
                TableId::TypeDef,
                TableId::TypeRef,
                TableId::TypeSpec,
                TableId::Field,
                TableId::MethodDef,
            ],
            TableId::MethodDef => &[TableId::Param],
            TableId::InterfaceImpl | TableId::Event => {
                &[TableId::TypeDef, TableId::TypeRef, TableId::TypeSpec]
            }
            TableId::MemberRef => &[
                TableId::TypeDef,
                TableId::TypeRef,
                TableId::ModuleRef,
                TableId::MethodDef,
                TableId::TypeSpec,
            ],
            TableId::Constant => &[TableId::Field, TableId::Param, TableId::Property],
            TableId::CustomAttribute => &[
                // HasCustomAttribute covers many tables
                TableId::MethodDef,
                TableId::Field,
                TableId::TypeRef,
                TableId::TypeDef,
                TableId::Param,
                TableId::InterfaceImpl,
                TableId::MemberRef,
                TableId::Module,
                TableId::DeclSecurity,
                TableId::Property,
                TableId::Event,
                TableId::StandAloneSig,
                TableId::ModuleRef,
                TableId::TypeSpec,
                TableId::Assembly,
                TableId::AssemblyRef,
                TableId::File,
                TableId::ExportedType,
                TableId::ManifestResource,
                TableId::GenericParam,
                TableId::GenericParamConstraint,
                TableId::MethodSpec,
            ],
            TableId::FieldMarshal => &[TableId::Field, TableId::Param],
            TableId::DeclSecurity => &[TableId::TypeDef, TableId::MethodDef, TableId::Assembly],
            TableId::ClassLayout | TableId::NestedClass => &[TableId::TypeDef],
            TableId::FieldLayout | TableId::FieldRVA => &[TableId::Field],
            TableId::EventMap => &[TableId::TypeDef, TableId::Event],
            TableId::PropertyMap => &[TableId::TypeDef, TableId::Property],
            TableId::MethodSemantics => &[TableId::MethodDef, TableId::Event, TableId::Property],
            TableId::MethodImpl => &[TableId::TypeDef, TableId::MethodDef, TableId::MemberRef],
            TableId::ImplMap => &[TableId::Field, TableId::MethodDef, TableId::ModuleRef],
            TableId::ExportedType => &[TableId::File, TableId::AssemblyRef, TableId::ExportedType],
            TableId::ManifestResource => {
                &[TableId::File, TableId::AssemblyRef, TableId::ExportedType]
            }
            TableId::GenericParam => &[TableId::TypeDef, TableId::MethodDef],
            TableId::MethodSpec => &[TableId::MethodDef, TableId::MemberRef],
            TableId::GenericParamConstraint => &[
                TableId::GenericParam,
                TableId::TypeDef,
                TableId::TypeRef,
                TableId::TypeSpec,
            ],
            TableId::FieldPtr => &[TableId::Field],
            TableId::MethodPtr => &[TableId::MethodDef],
            TableId::ParamPtr => &[TableId::Param],
            TableId::EventPtr => &[TableId::Event],
            TableId::PropertyPtr => &[TableId::Property],
            TableId::AssemblyRefProcessor | TableId::AssemblyRefOS => &[TableId::AssemblyRef],
            TableId::MethodDebugInformation => &[TableId::Document],
            TableId::LocalScope => &[
                TableId::MethodDef,
                TableId::ImportScope,
                TableId::LocalVariable,
                TableId::LocalConstant,
            ],
            TableId::ImportScope => &[TableId::ImportScope],
            TableId::StateMachineMethod => &[TableId::MethodDef],
            TableId::CustomDebugInformation => &[
                // HasCustomDebugInformation: HasCustomAttribute's tables and the PDB's own
                TableId::MethodDef,
                TableId::Field,
                TableId::TypeRef,
                TableId::TypeDef,
                TableId::Param,
                TableId::InterfaceImpl,
                TableId::MemberRef,
                TableId::Module,
                TableId::DeclSecurity,
                TableId::Property,
                TableId::Event,
                TableId::StandAloneSig,
                TableId::ModuleRef,
                TableId::TypeSpec,
                TableId::Assembly,
                TableId::AssemblyRef,
                TableId::File,
                TableId::ExportedType,
                TableId::ManifestResource,
                TableId::GenericParam,
                TableId::GenericParamConstraint,
                TableId::MethodSpec,
                TableId::Document,
                TableId::LocalScope,
                TableId::LocalVariable,
                TableId::LocalConstant,
                TableId::ImportScope,
            ],
            // Tables without cross-table references
            _ => &[],
        }
    }
}

/// Macro that provides unified dispatch from TableId enum values to their corresponding Raw table types.
///
/// This macro eliminates code duplication across the framework by providing a single source of truth
/// for TableId → Raw type mapping. It takes an expression that will be applied to each Raw type,
/// enabling generic operations across all metadata table types.
///
/// # Usage Examples
///
/// For table row size calculation:
/// ```no_run
/// use crate::metadata::tables::dispatch_table_type;
/// dispatch_table_type!(table_id, |RawType| RawType::row_size(table_info))
/// ```
///
/// For table writing operations:
/// ```no_run
/// use crate::metadata::tables::dispatch_table_type;
/// dispatch_table_type!(table_id, |RawType| {
///     if let Some(table) = self.tables_header.table::<RawType>() {
///         self.write_typed_table(table, table_offset)
///     } else {
///         Ok(0)
///     }
/// })
/// ```
///
/// For generic table operations:
/// ```no_run
/// use crate::metadata::tables::dispatch_table_type;
/// dispatch_table_type!(table_id, |RawType| {
///     // Any operation that needs to work with the concrete Raw type
///     process_table::<RawType>(context)
/// })
/// ```
///
/// # Design Pattern
///
/// This macro implements the "dispatch to concrete type" pattern, allowing code to:
/// 1. Accept a runtime `TableId` value
/// 2. Map it to the corresponding compile-time `*Raw` type
/// 3. Execute type-specific operations with full type safety
/// 4. Avoid large match statements and code duplication
///
/// The pattern is essential for metadata operations that need to work generically
/// across all table types while maintaining type safety and performance.
///
/// # Framework Usage
///
/// This macro is successfully used throughout the framework for:
/// - Table row size calculations during binary generation
/// - Table writing operations during assembly serialization  
/// - Any scenario requiring TableId → Raw type dispatch with uniform operations
#[macro_export]
macro_rules! dispatch_table_type {
    ($table_id:expr, |$RawType:ident| $expr:expr) => {
        match $table_id {
            $crate::metadata::tables::TableId::Module => {
                type $RawType = $crate::metadata::tables::ModuleRaw;
                $expr
            }
            $crate::metadata::tables::TableId::TypeRef => {
                type $RawType = $crate::metadata::tables::TypeRefRaw;
                $expr
            }
            $crate::metadata::tables::TableId::TypeDef => {
                type $RawType = $crate::metadata::tables::TypeDefRaw;
                $expr
            }
            $crate::metadata::tables::TableId::FieldPtr => {
                type $RawType = $crate::metadata::tables::FieldPtrRaw;
                $expr
            }
            $crate::metadata::tables::TableId::Field => {
                type $RawType = $crate::metadata::tables::FieldRaw;
                $expr
            }
            $crate::metadata::tables::TableId::MethodPtr => {
                type $RawType = $crate::metadata::tables::MethodPtrRaw;
                $expr
            }
            $crate::metadata::tables::TableId::MethodDef => {
                type $RawType = $crate::metadata::tables::MethodDefRaw;
                $expr
            }
            $crate::metadata::tables::TableId::ParamPtr => {
                type $RawType = $crate::metadata::tables::ParamPtrRaw;
                $expr
            }
            $crate::metadata::tables::TableId::Param => {
                type $RawType = $crate::metadata::tables::ParamRaw;
                $expr
            }
            $crate::metadata::tables::TableId::InterfaceImpl => {
                type $RawType = $crate::metadata::tables::InterfaceImplRaw;
                $expr
            }
            $crate::metadata::tables::TableId::MemberRef => {
                type $RawType = $crate::metadata::tables::MemberRefRaw;
                $expr
            }
            $crate::metadata::tables::TableId::Constant => {
                type $RawType = $crate::metadata::tables::ConstantRaw;
                $expr
            }
            $crate::metadata::tables::TableId::CustomAttribute => {
                type $RawType = $crate::metadata::tables::CustomAttributeRaw;
                $expr
            }
            $crate::metadata::tables::TableId::FieldMarshal => {
                type $RawType = $crate::metadata::tables::FieldMarshalRaw;
                $expr
            }
            $crate::metadata::tables::TableId::DeclSecurity => {
                type $RawType = $crate::metadata::tables::DeclSecurityRaw;
                $expr
            }
            $crate::metadata::tables::TableId::ClassLayout => {
                type $RawType = $crate::metadata::tables::ClassLayoutRaw;
                $expr
            }
            $crate::metadata::tables::TableId::FieldLayout => {
                type $RawType = $crate::metadata::tables::FieldLayoutRaw;
                $expr
            }
            $crate::metadata::tables::TableId::StandAloneSig => {
                type $RawType = $crate::metadata::tables::StandAloneSigRaw;
                $expr
            }
            $crate::metadata::tables::TableId::EventMap => {
                type $RawType = $crate::metadata::tables::EventMapRaw;
                $expr
            }
            $crate::metadata::tables::TableId::EventPtr => {
                type $RawType = $crate::metadata::tables::EventPtrRaw;
                $expr
            }
            $crate::metadata::tables::TableId::Event => {
                type $RawType = $crate::metadata::tables::EventRaw;
                $expr
            }
            $crate::metadata::tables::TableId::PropertyMap => {
                type $RawType = $crate::metadata::tables::PropertyMapRaw;
                $expr
            }
            $crate::metadata::tables::TableId::PropertyPtr => {
                type $RawType = $crate::metadata::tables::PropertyPtrRaw;
                $expr
            }
            $crate::metadata::tables::TableId::Property => {
                type $RawType = $crate::metadata::tables::PropertyRaw;
                $expr
            }
            $crate::metadata::tables::TableId::MethodSemantics => {
                type $RawType = $crate::metadata::tables::MethodSemanticsRaw;
                $expr
            }
            $crate::metadata::tables::TableId::MethodImpl => {
                type $RawType = $crate::metadata::tables::MethodImplRaw;
                $expr
            }
            $crate::metadata::tables::TableId::ModuleRef => {
                type $RawType = $crate::metadata::tables::ModuleRefRaw;
                $expr
            }
            $crate::metadata::tables::TableId::TypeSpec => {
                type $RawType = $crate::metadata::tables::TypeSpecRaw;
                $expr
            }
            $crate::metadata::tables::TableId::ImplMap => {
                type $RawType = $crate::metadata::tables::ImplMapRaw;
                $expr
            }
            $crate::metadata::tables::TableId::FieldRVA => {
                type $RawType = $crate::metadata::tables::FieldRvaRaw;
                $expr
            }
            $crate::metadata::tables::TableId::EncLog => {
                type $RawType = $crate::metadata::tables::EncLogRaw;
                $expr
            }
            $crate::metadata::tables::TableId::EncMap => {
                type $RawType = $crate::metadata::tables::EncMapRaw;
                $expr
            }
            $crate::metadata::tables::TableId::Assembly => {
                type $RawType = $crate::metadata::tables::AssemblyRaw;
                $expr
            }
            $crate::metadata::tables::TableId::AssemblyProcessor => {
                type $RawType = $crate::metadata::tables::AssemblyProcessorRaw;
                $expr
            }
            $crate::metadata::tables::TableId::AssemblyOS => {
                type $RawType = $crate::metadata::tables::AssemblyOsRaw;
                $expr
            }
            $crate::metadata::tables::TableId::AssemblyRef => {
                type $RawType = $crate::metadata::tables::AssemblyRefRaw;
                $expr
            }
            $crate::metadata::tables::TableId::AssemblyRefProcessor => {
                type $RawType = $crate::metadata::tables::AssemblyRefProcessorRaw;
                $expr
            }
            $crate::metadata::tables::TableId::AssemblyRefOS => {
                type $RawType = $crate::metadata::tables::AssemblyRefOsRaw;
                $expr
            }
            $crate::metadata::tables::TableId::File => {
                type $RawType = $crate::metadata::tables::FileRaw;
                $expr
            }
            $crate::metadata::tables::TableId::ExportedType => {
                type $RawType = $crate::metadata::tables::ExportedTypeRaw;
                $expr
            }
            $crate::metadata::tables::TableId::ManifestResource => {
                type $RawType = $crate::metadata::tables::ManifestResourceRaw;
                $expr
            }
            $crate::metadata::tables::TableId::NestedClass => {
                type $RawType = $crate::metadata::tables::NestedClassRaw;
                $expr
            }
            $crate::metadata::tables::TableId::GenericParam => {
                type $RawType = $crate::metadata::tables::GenericParamRaw;
                $expr
            }
            $crate::metadata::tables::TableId::MethodSpec => {
                type $RawType = $crate::metadata::tables::MethodSpecRaw;
                $expr
            }
            $crate::metadata::tables::TableId::GenericParamConstraint => {
                type $RawType = $crate::metadata::tables::GenericParamConstraintRaw;
                $expr
            }
            $crate::metadata::tables::TableId::Document => {
                type $RawType = $crate::metadata::tables::DocumentRaw;
                $expr
            }
            $crate::metadata::tables::TableId::MethodDebugInformation => {
                type $RawType = $crate::metadata::tables::MethodDebugInformationRaw;
                $expr
            }
            $crate::metadata::tables::TableId::LocalScope => {
                type $RawType = $crate::metadata::tables::LocalScopeRaw;
                $expr
            }
            $crate::metadata::tables::TableId::LocalVariable => {
                type $RawType = $crate::metadata::tables::LocalVariableRaw;
                $expr
            }
            $crate::metadata::tables::TableId::LocalConstant => {
                type $RawType = $crate::metadata::tables::LocalConstantRaw;
                $expr
            }
            $crate::metadata::tables::TableId::ImportScope => {
                type $RawType = $crate::metadata::tables::ImportScopeRaw;
                $expr
            }
            $crate::metadata::tables::TableId::StateMachineMethod => {
                type $RawType = $crate::metadata::tables::StateMachineMethodRaw;
                $expr
            }
            $crate::metadata::tables::TableId::CustomDebugInformation => {
                type $RawType = $crate::metadata::tables::CustomDebugInformationRaw;
                $expr
            }
        }
    };
}

//! TypeDef metadata table support for .NET assemblies.
//!
//! This module provides comprehensive support for the `TypeDef` metadata table (ID 0x02), which
//! defines all types (classes, interfaces, value types, enums, delegates) within the current
//! assembly. The `TypeDef` table is fundamental to the .NET type system and serves as the primary
//! source of type definitions for metadata consumers.
//!
//! # Architecture
//!
//! The module is built around the ECMA-335 TypeDef table structure, providing both raw
//! table access and processed type representations. The architecture supports efficient
//! type lookups, member enumeration, and integration with the broader type system.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::typedef::TypeDefRaw`] - Raw table entry representation
//! - [`crate::metadata::loader::tables::TypeDefLoader`] - Table loading functionality  
//! - [`crate::metadata::tables::typedef::TypeAttributes`] - Type attribute flag constants
//!
//! # Table Structure
//!
//! The `TypeDef` table contains the following columns as specified in ECMA-335:
//! - **Flags** (4-byte bitmask): [`crate::metadata::tables::typedef::TypeAttributes`] controlling visibility, layout, and semantics
//! - **`TypeName`** (string heap index): Simple name of the type (without namespace)
//! - **`TypeNamespace`** (string heap index): Namespace containing the type (empty for global types)
//! - **`Extends`** (coded index): Base type reference (`TypeDef`, `TypeRef`, or `TypeSpec`)
//! - **`FieldList`** (Field table index): First field belonging to this type
//! - **`MethodList`** (`MethodDef` table index): First method belonging to this type
//!
//! # Type System Integration
//!
//! `TypeDef` entries are processed and converted into [`crate::metadata::typesystem::CilType`]
//! instances that provide high-level type system operations:
//! - Type hierarchy navigation and inheritance resolution
//! - Member enumeration (fields, methods, properties, events)
//! - Generic type parameter and constraint handling
//! - Custom attribute association and retrieval
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::tables::TypeAttributes;
//!
//! // Check if a type is public
//! let flags = TypeAttributes::PUBLIC;
//! let is_public = (flags & TypeAttributes::VISIBILITY_MASK) == TypeAttributes::PUBLIC;
//! assert!(is_public);
//!
//! // Check if a type is abstract
//! let is_abstract = (flags & TypeAttributes::ABSTRACT) != TypeAttributes::ZERO;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All types in this module are [`std::marker::Send`] and [`std::marker::Sync`] as they contain
//! only primitive data and static references. Type attribute constants are safe to share
//! across threads without synchronization.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::typesystem`] - Provides processed type representations
//! - [`crate::metadata::tables`] - Part of the broader metadata table system
//! - [`crate::metadata::tables::field`] - Related field definitions
//! - [`crate::metadata::tables::methoddef`] - Related method definitions
//!
//! ## ECMA-335 Reference
//!
//! See ECMA-335, Partition II, Section 22.37 for the complete `TypeDef` table specification.
//!
//! **Table ID**: `0x02`

mod builder;
mod raw;
mod reader;
mod writer;

pub use builder::*;
pub use raw::*;

metadata_flags! {
    /// Type attribute flags for `TypeDef` entries (ECMA-335 §II.23.1.15).
    ///
    /// Strongly-typed wrapper around the 4-byte `TypeDef.Flags` bitmask controlling
    /// type visibility, layout, semantics, and interoperability characteristics.
    /// The flags are organized into logical groups with corresponding mask constants
    /// for efficient bit extraction.
    ///
    /// ## Visibility Flags
    /// Control type accessibility and nested type visibility:
    /// - [`crate::metadata::tables::typedef::TypeAttributes::NOT_PUBLIC`] / [`crate::metadata::tables::typedef::TypeAttributes::PUBLIC`] - Top-level type visibility
    /// - [`crate::metadata::tables::typedef::TypeAttributes::NESTED_PUBLIC`], [`crate::metadata::tables::typedef::TypeAttributes::NESTED_PRIVATE`], etc. - Nested type accessibility levels
    ///
    /// ## Layout Flags
    /// Control how type fields are arranged in memory:
    /// - [`crate::metadata::tables::typedef::TypeAttributes::AUTO_LAYOUT`] - Runtime-determined field layout (default)
    /// - [`crate::metadata::tables::typedef::TypeAttributes::SEQUENTIAL_LAYOUT`] - Fields laid out in declaration order
    /// - [`crate::metadata::tables::typedef::TypeAttributes::EXPLICIT_LAYOUT`] - Explicit field offsets specified
    ///
    /// ## Semantic Flags
    /// Control type behavior and characteristics:
    /// - [`crate::metadata::tables::typedef::TypeAttributes::CLASS`] / [`crate::metadata::tables::typedef::TypeAttributes::INTERFACE`] - Type category
    /// - [`crate::metadata::tables::typedef::TypeAttributes::ABSTRACT`] / [`crate::metadata::tables::typedef::TypeAttributes::SEALED`] - Inheritance modifiers
    /// - [`crate::metadata::tables::typedef::TypeAttributes::SPECIAL_NAME`] / [`crate::metadata::tables::typedef::TypeAttributes::IMPORT`] / [`crate::metadata::tables::typedef::TypeAttributes::SERIALIZABLE`] - Special attributes
    ///
    /// ## Interop Flags
    /// Control string handling for native interoperability:
    /// - [`crate::metadata::tables::typedef::TypeAttributes::ANSI_CLASS`] / [`crate::metadata::tables::typedef::TypeAttributes::UNICODE_CLASS`] / [`TypeAttributes::AUTO_CLASS`] - String encoding
    /// - [`crate::metadata::tables::typedef::TypeAttributes::CUSTOM_FORMAT_CLASS`] - Custom string format
    pub struct TypeAttributes(u32);
}

impl TypeAttributes {
    /// Mask for extracting type visibility information.
    ///
    /// Use this mask with bitwise AND to isolate the 3 visibility bits,
    /// then compare with specific visibility constants.
    pub const VISIBILITY_MASK: Self = Self(0x0000_0007);

    /// Type has no public scope (internal to assembly).
    ///
    /// This is the default visibility for top-level types that are not
    /// explicitly declared as public.
    pub const NOT_PUBLIC: Self = Self(0x0000_0000);

    /// Type has public scope (visible outside assembly).
    ///
    /// Public types can be accessed from other assemblies and form
    /// part of the assembly's public API surface.
    pub const PUBLIC: Self = Self(0x0000_0001);

    /// Nested type with public visibility.
    ///
    /// The nested type is accessible wherever the enclosing type is accessible,
    /// providing unrestricted access within that scope.
    pub const NESTED_PUBLIC: Self = Self(0x0000_0002);

    /// Nested type with private visibility.
    ///
    /// The nested type is only accessible within the enclosing type,
    /// providing the most restrictive access level.
    pub const NESTED_PRIVATE: Self = Self(0x0000_0003);

    /// Nested type with family (protected) visibility.
    ///
    /// The nested type is accessible within the enclosing type and
    /// types that inherit from the enclosing type.
    pub const NESTED_FAMILY: Self = Self(0x0000_0004);

    /// Nested type with assembly (internal) visibility.
    ///
    /// The nested type is accessible within the same assembly as
    /// the enclosing type, but not from other assemblies.
    pub const NESTED_ASSEMBLY: Self = Self(0x0000_0005);

    /// Nested type with family AND assembly visibility.
    ///
    /// The nested type is accessible only to derived types within
    /// the same assembly (intersection of family and assembly).
    pub const NESTED_FAM_AND_ASSEM: Self = Self(0x0000_0006);

    /// Nested type with family OR assembly visibility.
    ///
    /// The nested type is accessible to derived types OR types within
    /// the same assembly (union of family and assembly).
    pub const NESTED_FAM_OR_ASSEM: Self = Self(0x0000_0007);

    /// Mask for extracting class layout information.
    ///
    /// Use this mask with bitwise AND to isolate the 2 layout bits,
    /// then compare with specific layout constants.
    pub const LAYOUT_MASK: Self = Self(0x0000_0018);

    /// Class fields are automatically laid out by the runtime.
    ///
    /// The runtime determines the most efficient field arrangement,
    /// which may not match declaration order. This is the default layout.
    pub const AUTO_LAYOUT: Self = Self(0x0000_0000);

    /// Class fields are laid out sequentially in declaration order.
    ///
    /// Fields appear in memory in the same order they are declared
    /// in source code, enabling predictable layout for interop scenarios.
    pub const SEQUENTIAL_LAYOUT: Self = Self(0x0000_0008);

    /// Field layout is explicitly specified using field offsets.
    ///
    /// Each field's position is explicitly controlled using
    /// [`crate::metadata::tables::fieldlayout::FieldLayoutRaw`] entries, providing
    /// complete control over type layout.
    pub const EXPLICIT_LAYOUT: Self = Self(0x0000_0010);

    /// Mask for extracting class semantics information.
    ///
    /// Use this mask to determine if the type is a class or interface.
    pub const CLASS_SEMANTICS_MASK: Self = Self(0x0000_0020);

    /// Type is a class (reference or value type).
    ///
    /// Classes can contain fields, methods, properties, and events.
    /// This includes both reference types and value types (structs).
    pub const CLASS: Self = Self(0x0000_0000);

    /// Type is an interface definition.
    ///
    /// Interfaces define contracts with method signatures, properties,
    /// and events, but cannot contain fields or implementation.
    pub const INTERFACE: Self = Self(0x0000_0020);

    /// Class is abstract and cannot be instantiated directly.
    ///
    /// Abstract classes may contain abstract methods that must be
    /// implemented by derived classes.
    pub const ABSTRACT: Self = Self(0x0000_0080);

    /// Class is sealed and cannot be inherited from.
    ///
    /// Sealed classes represent final implementations that cannot
    /// be extended through inheritance.
    pub const SEALED: Self = Self(0x0000_0100);

    /// Class name has special meaning to the runtime.
    ///
    /// Types with special names follow specific naming conventions
    /// and may receive special treatment from the runtime.
    pub const SPECIAL_NAME: Self = Self(0x0000_0400);

    /// Class/Interface is imported from external metadata.
    ///
    /// Imported types are defined in other assemblies or modules
    /// and referenced within this assembly.
    pub const IMPORT: Self = Self(0x0000_1000);

    /// Type is serializable (legacy attribute).
    ///
    /// This flag indicates the type supports binary serialization.
    /// Modern .NET uses attributes for serialization control.
    pub const SERIALIZABLE: Self = Self(0x0000_2000);

    /// Mask for extracting string format information for native interop.
    ///
    /// Use this mask to determine how string parameters are marshaled
    /// when calling native (unmanaged) code.
    pub const STRING_FORMAT_MASK: Self = Self(0x0003_0000);

    /// String parameters are marshaled as ANSI (single-byte) strings.
    ///
    /// LPSTR parameters use single-byte character encoding, typically
    /// the system's default ANSI code page.
    pub const ANSI_CLASS: Self = Self(0x0000_0000);

    /// String parameters are marshaled as Unicode (UTF-16) strings.
    ///
    /// LPSTR parameters use UTF-16 encoding with 2-byte characters,
    /// which is the native .NET string format.
    pub const UNICODE_CLASS: Self = Self(0x0001_0000);

    /// String parameter marshaling is determined automatically.
    ///
    /// The runtime selects ANSI or Unicode marshaling based on the
    /// target platform and API requirements.
    pub const AUTO_CLASS: Self = Self(0x0002_0000);

    /// String parameters use a custom marshaling format.
    ///
    /// Custom string marshaling behavior is defined by additional
    /// metadata or runtime-specific handling.
    pub const CUSTOM_FORMAT_CLASS: Self = Self(0x0003_0000);

    /// Mask for custom string format encoding information.
    ///
    /// These bits provide additional encoding details when using
    /// [`TypeAttributes::CUSTOM_FORMAT_CLASS`]. The specific meaning is implementation-defined.
    pub const CUSTOM_STRING_FORMAT_MASK: Self = Self(0x00C0_0000);

    /// Type initializer is called before first access to any static field.
    ///
    /// When set, the runtime guarantees the type initializer (`.cctor`) runs
    /// before the first access to any static field of the type, rather than
    /// at some earlier point determined by the runtime.
    pub const BEFORE_FIELD_INIT: Self = Self(0x0010_0000);

    /// Runtime should check name encoding and treat specially.
    ///
    /// Types with this flag have names that the runtime treats specially,
    /// similar to [`TypeAttributes::SPECIAL_NAME`] but specifically for runtime-internal use.
    pub const RT_SPECIAL_NAME: Self = Self(0x0000_0800);

    /// Type is a type forwarder to another assembly.
    ///
    /// Used in `ExportedType` table entries to indicate that the type has been
    /// moved to a different assembly and references should be forwarded there.
    pub const FORWARDER: Self = Self(0x0020_0000);

    /// Extracts the visibility portion of the flags.
    #[inline]
    #[must_use]
    pub const fn visibility(self) -> Self {
        Self(self.0 & Self::VISIBILITY_MASK.0)
    }

    /// Extracts the layout portion of the flags.
    #[inline]
    #[must_use]
    pub const fn layout(self) -> Self {
        Self(self.0 & Self::LAYOUT_MASK.0)
    }

    /// Extracts the string format portion of the flags.
    #[inline]
    #[must_use]
    pub const fn string_format(self) -> Self {
        Self(self.0 & Self::STRING_FORMAT_MASK.0)
    }

    /// Returns the ILAsm keyword for the visibility portion of the flags.
    #[must_use]
    pub fn visibility_keyword(self) -> &'static str {
        match self.visibility() {
            Self::NOT_PUBLIC => "private",
            Self::PUBLIC => "public",
            Self::NESTED_PUBLIC => "nested public",
            Self::NESTED_PRIVATE => "nested private",
            Self::NESTED_FAMILY => "nested family",
            Self::NESTED_ASSEMBLY => "nested assembly",
            Self::NESTED_FAM_AND_ASSEM => "nested famandassem",
            Self::NESTED_FAM_OR_ASSEM => "nested famorassem",
            _ => "",
        }
    }

    /// Returns the ILAsm keyword for the layout portion of the flags.
    #[must_use]
    pub fn layout_keyword(self) -> &'static str {
        match self.layout() {
            Self::SEQUENTIAL_LAYOUT => "sequential",
            Self::EXPLICIT_LAYOUT => "explicit",
            _ => "auto",
        }
    }

    /// Returns the ILAsm keyword for the string format portion of the flags.
    #[must_use]
    pub fn string_format_keyword(self) -> &'static str {
        match self.string_format() {
            Self::UNICODE_CLASS => "unicode",
            Self::AUTO_CLASS => "autochar",
            _ => "ansi",
        }
    }

    /// Returns `true` if the type is an interface.
    #[inline]
    #[must_use]
    pub const fn is_interface(self) -> bool {
        self.contains(Self::INTERFACE)
    }

    /// Returns `true` if the type is abstract.
    #[inline]
    #[must_use]
    pub const fn is_abstract(self) -> bool {
        self.contains(Self::ABSTRACT)
    }

    /// Returns `true` if the type is sealed (cannot be inherited from).
    #[inline]
    #[must_use]
    pub const fn is_sealed(self) -> bool {
        self.contains(Self::SEALED)
    }

    /// Returns `true` if the type has the `BeforeFieldInit` flag.
    #[inline]
    #[must_use]
    pub const fn is_before_field_init(self) -> bool {
        self.contains(Self::BEFORE_FIELD_INIT)
    }

    /// Returns `true` if the type is serializable.
    #[inline]
    #[must_use]
    pub const fn is_serializable(self) -> bool {
        self.contains(Self::SERIALIZABLE)
    }

    /// Returns `true` if the type has a special name.
    #[inline]
    #[must_use]
    pub const fn is_special_name(self) -> bool {
        self.contains(Self::SPECIAL_NAME)
    }

    /// Returns `true` if the type has a runtime special name.
    #[inline]
    #[must_use]
    pub const fn is_rt_special_name(self) -> bool {
        self.contains(Self::RT_SPECIAL_NAME)
    }

    /// Returns `true` if the type is imported from external metadata.
    #[inline]
    #[must_use]
    pub const fn is_import(self) -> bool {
        self.contains(Self::IMPORT)
    }

    /// Returns `true` if the type is a type forwarder.
    #[inline]
    #[must_use]
    pub const fn is_forwarder(self) -> bool {
        self.contains(Self::FORWARDER)
    }

    /// Returns `true` if the type is publicly visible (top-level public or nested public).
    #[inline]
    #[must_use]
    pub fn is_public(self) -> bool {
        let vis = self.visibility();
        vis == Self::PUBLIC || vis == Self::NESTED_PUBLIC
    }

    /// Returns `true` if the type is a nested type (any nested visibility).
    #[inline]
    #[must_use]
    pub fn is_nested(self) -> bool {
        self.visibility().0 >= Self::NESTED_PUBLIC.0
    }
}

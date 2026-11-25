//! Field metadata table implementation.
//!
//! This module provides comprehensive support for the ECMA-335 Field metadata table (0x04),
//! which defines the fields (data members) that belong to types. Fields represent
//! the data storage structure of .NET types including instance fields, static fields,
//! constants, and literals with their associated types and characteristics. It includes raw
//! table access, resolved data structures, and integration with the broader metadata system.
//!
//! # Architecture
//!
//! This module follows the dual variant pattern for metadata table representation:
//! - **Raw Layer**: [`crate::metadata::tables::field::raw::FieldRaw`] provides direct binary access
//! - **Owned Layer**: [`crate::metadata::tables::field::owned::Field`] offers resolved, validated data
//!
//! # Key Components
//!
//! - **Raw Representation**: [`crate::metadata::tables::field::raw::FieldRaw`] - Direct binary table format with unresolved indexes
//! - **Owned Data**: [`crate::metadata::tables::field::owned::Field`] - Resolved entries with owned data and parsed signatures
//! - **Loading Infrastructure**: [`crate::metadata::loader::tables::FieldLoader`] - Processes raw entries during metadata loading
//! - **Type Aliases**: Collection types for managing Field entries efficiently
//! - **Attributes**: [`crate::metadata::tables::field::FieldAttributes`] module with field characteristic constants
//!
//! # Integration
//!
//! - Raw entries are processed by [`crate::metadata::loader::tables::FieldLoader`] during metadata loading
//! - Integrates with [`crate::metadata::streams::Strings`] for name resolution and [`crate::metadata::streams::Blob`] for signature parsing
//! - References type definitions through field ownership relationships
//!
//! # Field Table Structure
//!
//! Each Field entry contains:
//! - **Flags** (2 bytes): Field attributes bitmask controlling access and behavior
//! - **Name** (2/4 bytes): String heap index for the field name
//! - **Signature** (2/4 bytes): Blob heap index for the field type signature
//!
//! Fields are owned by types and define the data storage layout, access patterns,
//! and type information for both instance and static data members.
//!
//! # Field Attributes
//!
//! The [`FieldAttributes`] module provides constants for field characteristics:
//! - **Access Control**: Private, public, family, assembly, etc.
//! - **Storage Type**: Instance vs. static storage
//! - **Mutability**: Read-only, literal, initialization-only
//! - **Special Behavior**: Marshaling, P/Invoke, RVA, serialization
//!
//! # Reference
//! - [ECMA-335 II.22.15](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `Field` table specification
//! - [ECMA-335 II.23.1.5](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `FieldAttributes` specification

use std::sync::Arc;

use crossbeam_skiplist::SkipMap;

use crate::{metadata::token::Token, utils::LazyList};

mod builder;
mod owned;
mod raw;
mod reader;
mod writer;

pub use builder::*;
pub use owned::*;
pub use raw::*;

/// Thread-safe map of metadata tokens to Field entries
///
/// Provides efficient concurrent access to Field entries indexed by their
/// metadata tokens. Uses a lock-free skip list implementation for high-performance
/// concurrent reads and writes during metadata loading.
pub type FieldMap = SkipMap<Token, FieldRc>;

/// Thread-safe vector of Field entries
///
/// Provides a growable collection of Field entries with thread-safe append
/// operations. Used for collecting entries during parallel processing phases
/// of metadata loading. A list allocates its storage on its first push: a type reference
/// or a constructed type holds none.
pub type FieldList = LazyList<FieldRc>;

/// Reference-counted pointer to a Field entry
///
/// Provides shared ownership of [`Field`] instances across multiple
/// threads and data structures. Enables efficient memory usage and safe
/// concurrent access to Field metadata.
pub type FieldRc = Arc<Field>;

metadata_flags! {
    /// Field attribute flags for controlling field characteristics and behavior (ECMA-335 §II.23.1.5).
    ///
    /// Strongly-typed wrapper around the 2-byte `Field.Flags` bitmask that controls
    /// various aspects of field behavior including access control, storage type,
    /// mutability, and special runtime characteristics. These attributes are defined
    /// in the ECMA-335 specification and control how the runtime handles field access
    /// and storage.
    ///
    /// ## Attribute Categories
    ///
    /// ### Access Control (3-bit mask)
    /// Controls visibility and accessibility of the field from different contexts.
    ///
    /// ### Storage Type
    /// Determines whether the field is per-instance or shared across all instances.
    ///
    /// ### Mutability
    /// Controls when and how the field value can be modified.
    ///
    /// ### Special Characteristics
    /// Provides additional runtime behavior and metadata information.
    ///
    /// ## Reference
    /// - [ECMA-335 II.23.1.5](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `FieldAttributes` specification
    pub struct FieldAttributes(u32);
}

impl FieldAttributes {
    /// Mask for extracting access control bits from field attributes.
    ///
    /// Use this mask to isolate the 3-bit access control field from the
    /// complete attributes bitmask. The result can be compared against
    /// the individual access level constants.
    pub const FIELD_ACCESS_MASK: Self = Self(0x0007);

    /// Field not referenceable by user code.
    ///
    /// The field is controlled by the compiler and cannot be directly
    /// referenced or accessed by user code. Typically used for compiler-generated
    /// fields that support language features or runtime optimizations.
    pub const COMPILER_CONTROLLED: Self = Self(0x0000);

    /// Field accessible only by the parent type.
    ///
    /// Private fields can only be accessed by code within the same type
    /// definition. This is the most restrictive access level and provides
    /// strong encapsulation for internal type state.
    pub const PRIVATE: Self = Self(0x0001);

    /// Field accessible by subtypes only within this assembly.
    ///
    /// Family-and-assembly access combines family (inheritance) and assembly
    /// visibility requirements. The field is accessible to derived types
    /// but only when they are defined within the same assembly.
    pub const FAM_AND_ASSEM: Self = Self(0x0002);

    /// Field accessible by anyone within the assembly.
    ///
    /// Assembly-level access allows any code within the same assembly
    /// to access the field, regardless of type relationships or namespace
    /// organization.
    pub const ASSEMBLY: Self = Self(0x0003);

    /// Field accessible only by type and subtypes.
    ///
    /// Family access allows the declaring type and any derived types
    /// to access the field, regardless of assembly boundaries. This
    /// supports protected access patterns in inheritance hierarchies.
    pub const FAMILY: Self = Self(0x0004);

    /// Field accessible by subtypes anywhere, plus anyone in assembly.
    ///
    /// Family-or-assembly access combines the broadest interpretation
    /// of both family and assembly access. The field is accessible to
    /// derived types anywhere or to any code within the same assembly.
    pub const FAM_OR_ASSEM: Self = Self(0x0005);

    /// Field accessible by anyone who has visibility to this scope.
    ///
    /// Public access provides the broadest visibility, allowing any
    /// code that can reference the declaring type to access the field.
    /// This is the standard access level for public APIs.
    pub const PUBLIC: Self = Self(0x0006);

    /// Field is defined on type rather than per instance.
    ///
    /// Static fields are shared across all instances of a type and
    /// exist independently of any particular object instance. They
    /// are allocated once per type and persist for the application lifetime.
    pub const STATIC: Self = Self(0x0010);

    /// Field can only be initialized, not written after initialization.
    ///
    /// Read-only fields can only be assigned during object construction
    /// (in constructors or field initializers). After initialization,
    /// the field value cannot be modified, providing immutability guarantees.
    pub const INIT_ONLY: Self = Self(0x0020);

    /// Field value is a compile-time constant.
    ///
    /// Literal fields contain compile-time constant values that are
    /// embedded directly in the metadata. They do not consume storage
    /// in object instances and their values are resolved at compile time.
    pub const LITERAL: Self = Self(0x0040);

    /// Field should not be serialized when type is remoted.
    ///
    /// Reserved attribute indicating that the field should be excluded
    /// from serialization processes, particularly in remoting scenarios
    /// where object state is transmitted across application boundaries.
    pub const NOT_SERIALIZED: Self = Self(0x0080);

    /// Field has special name significance.
    ///
    /// Special name fields have particular significance to the runtime
    /// or language compilers. The specific behavior depends on the field
    /// name and is typically used for compiler-generated or runtime-special fields.
    pub const SPECIAL_NAME: Self = Self(0x0200);

    /// Implementation is forwarded through P/Invoke.
    ///
    /// P/Invoke implementation indicates that the field's implementation
    /// is provided through platform invoke mechanisms, typically for
    /// interoperability with native code libraries.
    pub const PINVOKE_IMPL: Self = Self(0x2000);

    /// CLI provides special behavior depending on the field name.
    ///
    /// Runtime special name fields receive special treatment from the
    /// Common Language Infrastructure based on their names. The specific
    /// behavior is determined by the CLI implementation and field naming conventions.
    pub const RTSPECIAL_NAME: Self = Self(0x0400);

    /// Field has associated marshaling information.
    ///
    /// Indicates that the field has marshaling information defined in
    /// the `FieldMarshal` table, specifying how the field should be
    /// marshaled when crossing managed/unmanaged boundaries.
    pub const HAS_FIELD_MARSHAL: Self = Self(0x1000);

    /// Field has a default value.
    ///
    /// Indicates that the field has a default value defined in the
    /// Constant table. This value is used when the field is not
    /// explicitly initialized during object construction.
    pub const HAS_DEFAULT: Self = Self(0x8000);

    /// Field has associated RVA (Relative Virtual Address).
    ///
    /// Indicates that the field has an associated RVA defined in the
    /// `FieldRVA` table, typically used for fields that map to specific
    /// memory locations or contain pre-initialized data.
    pub const HAS_FIELD_RVA: Self = Self(0x0100);

    /// Extracts the access control portion of the flags.
    #[inline]
    #[must_use]
    pub const fn access(self) -> Self {
        Self(self.0 & Self::FIELD_ACCESS_MASK.0)
    }

    /// Returns the ILAsm keyword for the access control portion of the flags.
    #[must_use]
    pub fn access_keyword(self) -> &'static str {
        match self.access() {
            Self::COMPILER_CONTROLLED => "privatescope",
            Self::PRIVATE => "private",
            Self::FAM_AND_ASSEM => "famandassem",
            Self::ASSEMBLY => "assembly",
            Self::FAMILY => "family",
            Self::FAM_OR_ASSEM => "famorassem",
            Self::PUBLIC => "public",
            _ => "",
        }
    }

    /// Returns `true` if the field is static.
    #[inline]
    #[must_use]
    pub const fn is_static(self) -> bool {
        self.contains(Self::STATIC)
    }

    /// Returns `true` if the field is init-only (readonly).
    #[inline]
    #[must_use]
    pub const fn is_init_only(self) -> bool {
        self.contains(Self::INIT_ONLY)
    }

    /// Returns `true` if the field is a compile-time literal.
    #[inline]
    #[must_use]
    pub const fn is_literal(self) -> bool {
        self.contains(Self::LITERAL)
    }

    /// Returns `true` if the field has the not-serialized flag.
    #[inline]
    #[must_use]
    pub const fn is_not_serialized(self) -> bool {
        self.contains(Self::NOT_SERIALIZED)
    }

    /// Returns `true` if the field has a special name.
    #[inline]
    #[must_use]
    pub const fn is_special_name(self) -> bool {
        self.contains(Self::SPECIAL_NAME)
    }

    /// Returns `true` if the field has a runtime special name.
    #[inline]
    #[must_use]
    pub const fn is_rt_special_name(self) -> bool {
        self.contains(Self::RTSPECIAL_NAME)
    }

    /// Returns `true` if the field has associated marshaling information.
    #[inline]
    #[must_use]
    pub const fn has_field_marshal(self) -> bool {
        self.contains(Self::HAS_FIELD_MARSHAL)
    }

    /// Returns `true` if the field has a default value.
    #[inline]
    #[must_use]
    pub const fn has_default(self) -> bool {
        self.contains(Self::HAS_DEFAULT)
    }

    /// Returns `true` if the field has an associated RVA.
    #[inline]
    #[must_use]
    pub const fn has_field_rva(self) -> bool {
        self.contains(Self::HAS_FIELD_RVA)
    }
}

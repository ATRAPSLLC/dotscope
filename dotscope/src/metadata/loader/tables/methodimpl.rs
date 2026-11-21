//! `MethodImpl` table loader implementation for .NET metadata processing.
//!
//! This module provides the [`crate::metadata::loader::tables::MethodImplLoader`] responsible for loading and processing
//! `MethodImpl` metadata table entries. The `MethodImpl` table defines method implementation
//! mappings that specify which concrete method implementation provides the behavior
//! for a given method declaration, essential for interface implementation and method
//! overriding in .NET type systems.
//!
//! # Architecture
//!
//! The loader implements a comprehensive method implementation mapping pipeline:
//! - **Parallel Processing**: Uses rayon for concurrent method implementation loading
//! - **Reference Resolution**: Resolves method and type references through coded indices
//! - **Mapping Application**: Applies implementation mappings to target types
//! - **Cross-Reference Building**: Establishes bidirectional implementation relationships
//! - **Validation**: Ensures implementation mappings are consistent and valid
//!
//! # Purpose
//!
//! The `MethodImpl` table is crucial for object-oriented programming and interface contracts:
//! - **Interface Implementation**: Maps interface method declarations to concrete implementations
//! - **Method Overriding**: Specifies which method implementations override base class methods
//! - **Explicit Implementation**: Handles explicit interface member implementation scenarios
//! - **Virtual Dispatch**: Establishes method resolution for polymorphic method calls
//! - **Generic Method Mapping**: Links generic method declarations to specialized implementations
//! - **Inheritance Support**: Enables proper method resolution in class hierarchies
//!
//! # Implementation Mapping Types
//!
//! `MethodImpl` entries support different kinds of method implementation scenarios:
//! - **Interface Implementations**: Concrete class methods implementing interface contracts
//! - **Virtual Method Overrides**: Derived class methods overriding base class virtual methods
//! - **Explicit Implementations**: Methods explicitly implementing specific interface members
//! - **Generic Specializations**: Specialized implementations for generic method instantiations
//! - **P/Invoke Mappings**: Native method implementations for managed method declarations
//! - **Abstract Method Implementations**: Concrete implementations of abstract method declarations
//!
//! # Loading Pipeline
//!
//! 1. **Dependency Validation**: Ensure TypeDef, TypeRef, MethodDef, and MemberRef tables are loaded
//! 2. **Parallel Processing**: Process MethodImpl entries concurrently using rayon
//! 3. **Reference Resolution**: Resolve class and method references through coded indices
//! 4. **Mapping Creation**: Create method implementation mapping objects
//! 5. **Application**: Apply mappings to target types for method resolution
//! 6. **Storage**: Store completed mappings in concurrent map
//!
//! # Table Dependencies
//!
//! - **TypeDef**: Required for resolving class types that contain implementation mappings
//! - **TypeRef**: Required for resolving external class types in inheritance scenarios
//! - **MethodDef**: Required for resolving concrete method implementations and declarations
//! - **MemberRef**: Required for resolving external method references in implementation mappings
//!
//! # Thread Safety
//!
//! All components in this module are designed for safe concurrent access:
//! - [`crate::metadata::loader::tables::MethodImplLoader`] is [`std::marker::Send`] and [`std::marker::Sync`]
//! - Loading operations use parallel processing via rayon for optimal efficiency
//! - Method implementation storage uses thread-safe concurrent data structures
//! - Reference resolution is coordinated safely across multiple threads
//!
//! # Integration
//!
//! This module integrates with:
//! - [`MethodImplRaw`] - Raw MethodImpl table representation
//! - [`TypeDefRaw`](crate::metadata::tables::TypeDefRaw) / [`CilType`](crate::metadata::typesystem::CilType) - Type definition table for class resolution
//! - [`MethodDefRaw`](crate::metadata::tables::MethodDefRaw) / [`Method`](crate::metadata::method::Method) - Method definition table for implementation resolution
//! - [`crate::metadata::loader`] - Metadata loading infrastructure and coordination
//!
//! # ECMA-335 Reference
//!
//! - [ECMA-335 Standard](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/)
//! - Partition II, §22.27 for the `MethodImpl` table specification
//! - Table ID: 0x19
//! - Purpose: Define method implementation mappings for interface and virtual method resolution
use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::MethodImplRaw,
    },
    prelude::TableId,
    utils::TryForEachInOrder,
    Result,
};

/// Loader implementation for the `MethodImpl` metadata table.
///
/// This loader processes method implementation mapping metadata, establishing connections
/// between method declarations and their concrete implementations. It handles interface
/// implementation mappings, method overriding relationships, and virtual dispatch
/// resolution for object-oriented programming support.
///
/// # Loading Strategy
///
/// The loader implements a sophisticated processing strategy:
/// - **Concurrent Processing**: Uses parallel iteration for optimal efficiency
/// - **Dependency Management**: Ensures TypeDef, TypeRef, MethodDef, and MemberRef tables are available
/// - **Reference Resolution**: Resolves coded indices to actual method and type references
/// - **Application Logic**: Applies implementation mappings to establish virtual method tables
///
/// # Thread Safety
///
/// [`MethodImplLoader`] is [`std::marker::Send`] and [`std::marker::Sync`], enabling safe concurrent use.
/// All operations are thread-safe and can be called from multiple threads simultaneously.
pub struct MethodImplLoader;

impl MetadataLoader for MethodImplLoader {
    /// Loads `MethodImpl` table entries and establishes method implementation mappings.
    ///
    /// This method iterates through all `MethodImpl` table entries, resolving class and method
    /// references to create concrete implementation mappings. Each entry is converted to an
    /// owned structure and applied to the type system for method resolution support.
    ///
    /// # Processing Steps
    ///
    /// 1. **Validation**: Verify required metadata streams are available
    /// 2. **Table Access**: Get MethodImpl table from metadata header
    /// 3. **Parallel Iteration**: Process entries concurrently using rayon
    /// 4. **Reference Resolution**: Resolve class and method references through coded indices
    /// 5. **Mapping Creation**: Create method implementation mapping objects
    /// 6. **Application**: Apply mappings to establish virtual method tables
    /// 7. **Storage**: Insert completed mappings into context map
    ///
    /// # Arguments
    ///
    /// * `context` - The loading context containing metadata tables and type resolution
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If all `MethodImpl` entries were processed successfully
    /// * `Err(_)` - If class resolution, method resolution, or mapping application fails
    ///
    /// # Errors
    ///
    /// This method can fail due to:
    /// - **Missing Dependencies**: Required TypeDef, TypeRef, MethodDef, or MemberRef tables not loaded
    /// - **Invalid References**: Malformed coded indices or missing target methods/types
    /// - **Mapping Conflicts**: Conflicting method implementation mappings
    /// - **Application Failures**: Failed to apply mappings to target types
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and uses parallel processing internally for optimal efficiency.
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let Some(header) = context.meta else {
            return Ok(());
        };
        let Some(table) = header.table::<MethodImplRaw>() else {
            return Ok(());
        };

        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row(row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("method impl 0x{:08x}", row.token.value());

                let Some(owned) = context.handle_result(
                    row.to_owned(|coded_index| context.get_ref(coded_index), context.types),
                    DiagnosticCategory::Method,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                context.handle_error(owned.apply(), DiagnosticCategory::Method, token_msg)?;
                context.method_impl.insert(row.token, owned);
                Ok(())
            })
    }

    /// Returns the table identifier for `MethodImpl`.
    ///
    /// # Returns
    ///
    /// The [`crate::metadata::tables::TableId::MethodImpl`] identifier (0x19) for this table type.
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::MethodImpl)
    }

    /// Returns the dependencies required for loading `MethodImpl` entries.
    ///
    /// `MethodImpl` table loading requires other tables to resolve implementation mappings:
    /// - [`crate::metadata::tables::TableId::TypeDef`] - For resolving class types containing implementation mappings
    /// - [`crate::metadata::tables::TableId::TypeRef`] - For resolving external class types in inheritance scenarios
    /// - [`crate::metadata::tables::TableId::MethodDef`] - For resolving concrete method implementations and declarations
    /// - [`crate::metadata::tables::TableId::MemberRef`] - For resolving external method references in mappings
    ///
    /// # Dependency Rationale
    ///
    /// **TypeDef Table**: Essential for resolving implementation class types including:
    /// - Class definitions that contain method implementations
    /// - Interface types that declare abstract methods
    /// - Generic type definitions with specialized implementations
    /// - Nested type definitions with inherited method mappings
    ///
    /// **TypeRef Table**: Required for external type resolution including:
    /// - External interface types from referenced assemblies
    /// - Base class types from external assemblies
    /// - Generic type instantiations with external type parameters
    /// - Cross-assembly inheritance and interface implementation
    ///
    /// **MethodDef Table**: Required for method implementation resolution including:
    /// - Concrete method implementations in classes
    /// - Virtual method declarations in base classes
    /// - Abstract method declarations in interfaces
    /// - Static and instance method implementations
    ///
    /// **MemberRef Table**: Required for external method reference resolution including:
    /// - External method declarations from referenced assemblies
    /// - Generic method instantiations with external parameters
    /// - P/Invoke method declarations for native implementations
    /// - Cross-assembly method overriding and implementation
    ///
    /// # Returns
    ///
    /// Static array of [`crate::metadata::tables::TableId`] values that must be loaded before `MethodImpl` processing.
    fn dependencies(&self) -> &'static [TableId] {
        &[
            TableId::TypeDef,
            TableId::TypeRef,
            TableId::MethodDef,
            TableId::MemberRef,
        ]
    }
}

//! # `TypeDef` Table Loader
//!
//! This module provides loading functionality for the `TypeDef` metadata table (ID 0x02).
//! The `TypeDef` table is the primary table for type definitions within a .NET assembly,
//! containing all types (classes, interfaces, enums, structs, delegates) defined in
//! the current assembly. This is one of the most critical tables in the metadata system.
//!
//! ## Purpose
//!
//! The `TypeDef` table serves as the foundation for type system operations:
//! - **Type Definitions**: Contains all types defined within the assembly
//! - **Type Hierarchy**: Establishes inheritance relationships and type structure
//! - **Member Organization**: Links types to their fields, methods, properties, and events
//! - **Metadata Integration**: Provides the core structure for the entire type system
//!
//! ## Loading Process
//!
//! 1. **Detection**: Checks if `TypeDef` table exists in metadata header
//! 2. **Parallel Phase 1**: Loads type definitions in parallel without base type resolution
//! 3. **String Resolution**: Resolves type names from the string heap
//! 4. **Member Linking**: Establishes connections to fields and methods
//! 5. **Type System Integration**: Registers types in the global type registry
//! 6. **Parallel Phase 2**: Resolves base types in parallel after all types are loaded
//! 7. **Validation**: Validates type structure and inheritance relationships
//!
//! ## Dependencies
//!
//! - **Field Table**: Required for field member resolution
//! - **`FieldPtr` Table**: Required for field indirection resolution
//! - **`MethodDef` Table**: Required for method member resolution
//! - **`MethodPtr` Table**: Required for method indirection resolution
//! - **`TypeRef` Table**: Required for base type and interface resolution
//!
//! ## Type System Integration
//!
//! `TypeDef` entries are integrated into the type system registry:
//! - **Global Registration**: Types are registered for cross-assembly access
//! - **Inheritance Chains**: Base type relationships are established
//! - **Generic Types**: Generic type definitions and constraints are processed
//! - **Nested Types**: Nested type relationships are maintained
//!
//! ## Thread Safety
//!
//! The loader uses thread-safe storage mechanisms for concurrent access to
//! type definitions across multiple threads during metadata loading.
//!
//! ## References
//!
//! - ECMA-335, Partition II, §22.37 - `TypeDef` table specification
//! - [`crate::metadata::tables::TypeDefRaw`] - Raw table entry structure
//! - [`crate::metadata::typesystem::CilType`] - Type system integration

use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::{MemberList, TableId, TypeDefRaw, TypeRefRaw},
        typesystem::CilTypeReference,
    },
    utils::TryForEachInOrder,
    Result,
};

/// Loader implementation for the `TypeDef` metadata table.
///
/// This loader processes `TypeDef` table entries (ID 0x02) that define all types
/// within the current assembly. It handles the loading, resolution, and integration
/// of type definitions with the broader metadata type system, establishing the
/// foundation for all type-related operations.
///
/// ## Loading Strategy
///
/// The loader employs a comprehensive type processing approach:
/// - Iterates through all `TypeDef` entries in declaration order
/// - Resolves type names and namespaces from string heap
/// - Links types to their field and method members
/// - Handles field and method pointer indirection when present
/// - Integrates types into the global type system registry
/// - Validates type structure and member relationships
///
/// ## Type Processing
///
/// Each type definition undergoes complete processing:
/// - **Name Resolution**: Type and namespace names from string heap
/// - **Member Linking**: Fields and methods are associated with the type
/// - **Hierarchy Setup**: Base types and interfaces are resolved
/// - **Generic Processing**: Generic parameters and constraints are handled
/// - **Attribute Processing**: Custom attributes are parsed and associated
///
/// ## Error Handling
///
/// The loader validates:
/// - Type definition structure and format
/// - Type name validity and uniqueness
/// - Member relationship consistency
/// - Generic parameter constraints and bounds
///
/// ## Thread Safety
///
/// This loader is thread-safe and integrates with thread-safe type system
/// storage for concurrent access during metadata loading operations.
pub struct TypeDefLoader;

impl MetadataLoader for TypeDefLoader {
    /// Loads and processes all `TypeDef` table entries from the metadata.
    ///
    /// This method loads all TypeDef entries in parallel without resolving base types,
    /// ensuring all types are available in the type registry for subsequent lookups.
    ///
    /// **Note**: Base type resolution is handled separately by the InheritanceResolver
    /// to avoid circular dependencies and provide unified inheritance processing.
    ///
    /// ## Arguments
    ///
    /// * `context` - The loading context containing metadata and storage facilities
    ///
    /// ## Returns
    ///
    /// * `Ok(())` - All type definitions loaded and validated successfully
    /// * `Err(_)` - Type loading or validation failed
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let (Some(header), Some(strings)) = (context.meta, context.strings) else {
            return Ok(());
        };
        let Some(table) = header.table::<TypeDefRaw>() else {
            return Ok(());
        };

        let field_ranges = context.member_ranges(header, MemberList::TypeDefFields);
        let method_ranges = context.member_ranges(header, MemberList::TypeDefMethods);

        let current_assembly_ref = context
            .assembly
            .get()
            .map(|assembly| CilTypeReference::Assembly(assembly.clone()));

        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row(row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("type 0x{:08x}", row.token.value());

                let Some(type_def) = context.handle_result(
                    row.to_owned(
                        |coded_index| context.get_ref(coded_index),
                        strings,
                        context.field,
                        &context.field_ptr,
                        context.method_def,
                        &context.method_ptr,
                        &field_ranges,
                        &method_ranges,
                        false, // Skip base type resolution - handled by InheritanceResolver
                        current_assembly_ref.clone(),
                    ),
                    DiagnosticCategory::Type,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                // A value type derives directly from `System.ValueType` or
                // `System.Enum` (ECMA-335 II.13). The base is linked later, by the
                // inheritance resolver, and a flavor computed before then would be
                // a class for good; the `extends` row's name settles it now.
                let names = |namespace: u32, name: u32| {
                    (
                        strings.get(namespace as usize).ok(),
                        strings.get(name as usize).ok(),
                    )
                };
                let base_name = match row.extends.tag {
                    TableId::TypeRef => header
                        .table::<TypeRefRaw>()
                        .and_then(|refs| refs.get(row.extends.row).ok().flatten())
                        .map(|base| names(base.type_namespace, base.type_name)),
                    TableId::TypeDef => table
                        .get(row.extends.row)
                        .ok()
                        .flatten()
                        .map(|base| names(base.type_namespace, base.type_name)),
                    _ => None,
                };
                // A value type extends System.ValueType or System.Enum, except System.Enum
                // itself, which extends System.ValueType and is a class (ECMA-335 II.13)
                let is_enum_itself =
                    names(row.type_namespace, row.type_name) == (Some("System"), Some("Enum"));
                if !is_enum_itself
                    && matches!(
                        base_name,
                        Some((Some("System"), Some("ValueType" | "Enum")))
                    )
                {
                    type_def.mark_value_type();
                }

                context.types.insert(&type_def);
                Ok(())
            })
    }

    /// Returns the table identifier for the `TypeDef` table.
    ///
    /// ## Returns
    ///
    /// [`TableId::TypeDef`] (0x02) - The metadata table identifier
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::TypeDef)
    }

    /// Returns the dependency list for `TypeDef` table loading.
    ///
    /// The `TypeDef` table depends on several other tables for proper type
    /// definition resolution and member linking:
    ///
    /// - **`Field`**: Required for field member resolution and type-field relationships
    /// - **`FieldPtr`**: Required for field pointer indirection when present
    /// - **`MethodDef`**: Required for method member resolution and type-method relationships
    /// - **`MethodPtr`**: Required for method pointer indirection when present
    /// - **`TypeRef`**: Required for base type and interface reference resolution
    ///
    /// ## Returns
    ///
    /// A slice containing the required table dependencies for type definition loading
    fn dependencies(&self) -> &'static [TableId] {
        &[
            TableId::Field,
            TableId::FieldPtr,
            TableId::MethodDef,
            TableId::MethodPtr,
            TableId::TypeRef,
        ]
    }
}

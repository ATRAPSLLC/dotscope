//! `GenericParam` table loader implementation.
//!
//! This module provides the [`GenericParamLoader`] responsible for loading and processing
//! `GenericParam` metadata table entries. The `GenericParam` table defines generic type and method
//! parameters, including their names, constraints, and variance specifications.
//!
//! # Purpose
//! The `GenericParam` table is used for generic programming support:
//! - **Generic types**: Type parameters for generic classes and interfaces
//! - **Generic methods**: Method-level type parameters for generic methods
//! - **Constraint specification**: Variance and constraint information for parameters
//! - **Name resolution**: Names for generic parameters used in signatures
//! - **Reflection support**: Runtime access to generic parameter metadata
//!
//! # Generic Parameter Context
//! Generic parameters enable type-safe generic programming:
//! - **Type parameters**: `class List<T>` defines type parameter T
//! - **Method parameters**: `void Method<U>()` defines method parameter U
//! - **Constraints**: `where T : IComparable<T>` specifies constraints
//! - **Variance**: `IEnumerable<out T>` specifies covariance
//! - **Multiple parameters**: `class Dictionary<TKey, TValue>` with multiple parameters
//!
//! # Table Dependencies
//! - **`TypeDef`**: Required for resolving generic type owners
//! - **`TypeRef`**: Required for external type references
//! - **`TypeSpec`**: Required for type specifications
//! - **`MethodDef`**: Required for resolving generic method owners
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.20 for the `GenericParam` table specification.

use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::GenericParamRaw,
    },
    prelude::TableId,
    utils::TryForEachInOrder,
    Result,
};

/// Loader implementation for the `GenericParam` metadata table.
///
/// This loader processes `GenericParam` table entries which define generic type and method
/// parameters. Each entry specifies a parameter's name, ordinal position, variance,
/// and owner (either a generic type or method).
///
/// # Errors
///
/// - Owner references cannot be resolved to types or methods
/// - String references cannot be resolved from the strings heap
/// - Memory allocation fails during processing
/// - Concurrent access conflicts occur
/// - Generic parameter application to owners fails
///
/// # ECMA-335 Reference
/// See ECMA-335, Partition II, §22.20 for complete `GenericParam` table specification.
pub struct GenericParamLoader;

impl MetadataLoader for GenericParamLoader {
    /// Load and process all `GenericParam` table entries.
    ///
    /// This method iterates through the `GenericParam` table, resolving owner and string
    /// references to build complete generic parameter structures. Each entry defines
    /// a generic parameter for a type or method.
    ///
    /// # Arguments
    /// * `context` - The loader context containing metadata tables and heaps
    ///
    /// # Returns
    /// Returns `Ok(())` on successful loading, or an error if:
    /// - Owner reference resolution fails
    /// - String reference resolution fails
    /// - Raw-to-owned conversion encounters issues
    /// - Parameter application to owners fails
    /// - Collection insertion operations fail
    /// - Parallel processing encounters errors
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let (Some(header), Some(strings)) = (context.meta, context.strings) else {
            return Ok(());
        };
        let Some(generics) = header.table::<GenericParamRaw>() else {
            return Ok(());
        };

        generics
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row(row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("generic param 0x{:08x}", row.token.value());

                let Some(owned) = context.handle_result(
                    row.to_owned(|coded_index| context.get_ref(coded_index), strings),
                    DiagnosticCategory::Type,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                context.handle_error(owned.apply(), DiagnosticCategory::Type, token_msg)?;
                context.generic_param.insert(row.token, owned.clone());
                Ok(())
            })
    }

    /// Returns the table identifier for the `GenericParam` table.
    ///
    /// # Returns
    /// Returns [`TableId::GenericParam`] indicating this loader handles the `GenericParam` table.
    ///
    /// [`TableId::GenericParam`]: crate::prelude::TableId::GenericParam
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::GenericParam)
    }

    /// Returns the table dependencies for `GenericParam` loading.
    ///
    /// The `GenericParam` table depends on multiple tables since generic parameters
    /// can be owned by either types or methods, and may reference various type constructs.
    ///
    /// # Returns
    /// Returns a slice containing the required table dependencies for proper
    /// generic parameter resolution and owner association.
    ///
    /// # Dependency Chain
    /// - **`TypeDef`**: Required for resolving generic type owners
    /// - **`TypeRef`**: Required for external type references in constraints
    /// - **`TypeSpec`**: Required for complex type specifications
    /// - **`MethodDef`**: Required for resolving generic method owners
    ///
    /// [`TableId::TypeDef`]: crate::prelude::TableId::TypeDef
    /// [`TableId::TypeRef`]: crate::prelude::TableId::TypeRef
    /// [`TableId::TypeSpec`]: crate::prelude::TableId::TypeSpec
    /// [`TableId::MethodDef`]: crate::prelude::TableId::MethodDef
    fn dependencies(&self) -> &'static [TableId] {
        &[
            TableId::TypeDef,
            TableId::TypeRef,
            TableId::TypeSpec,
            TableId::MethodDef,
        ]
    }
}

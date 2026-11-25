//! `GenericParamConstraint` table loader implementation.
//!
//! This module provides the [`GenericParamConstraintLoader`] responsible for loading and processing
//! `GenericParamConstraint` metadata table entries. The `GenericParamConstraint` table defines constraints
//! that apply to generic parameters, specifying base classes and interfaces that type arguments must satisfy.
//!
//! # Purpose
//! The `GenericParamConstraint` table is used for generic constraint enforcement:
//! - **Base class constraints**: Specifying required base classes for type arguments
//! - **Interface constraints**: Requiring type arguments to implement specific interfaces
//! - **Type safety**: Compile-time verification of constraint satisfaction
//! - **Code generation**: Enabling optimized code for constrained generics
//! - **Reflection support**: Runtime access to constraint information
//!
//! # Constraint Types
//! Constraints can specify various requirements:
//! - **Class constraints**: `where T : BaseClass` (inheritance requirement)
//! - **Interface constraints**: `where T : IInterface` (implementation requirement)
//! - **Multiple constraints**: `where T : BaseClass, IInterface1, IInterface2`
//! - **Nested constraints**: Constraints on parameters of generic constraints
//! - **Circular constraints**: `where T : IComparable<T>` (self-referential)
//!
//! # Table Dependencies
//! - **`GenericParam`**: Required for resolving generic parameter owners
//! - **`TypeDef`**: Required for internal type references in constraints
//! - **`TypeSpec`**: Required for type specifications in constraints
//! - **`TypeRef`**: Required for external type references in constraints
//! - **`MethodDef`**: Required for method-level generic parameter resolution
//! - **`MemberRef`**: Required for member references in constraints
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.21 for the `GenericParamConstraint` table specification.

use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::GenericParamConstraintRaw,
    },
    prelude::TableId,
    utils::TryForEachInOrder,
    Result,
};

/// Loader implementation for the `GenericParamConstraint` metadata table.
///
/// This loader processes `GenericParamConstraint` table entries which define constraints
/// that apply to generic parameters. Each entry specifies a type that serves as a
/// constraint for a generic parameter, enabling type-safe generic programming.
///
/// # Operations Performed
/// - **Parameter Resolution**: Resolves references to generic parameters
/// - **Type Resolution**: Resolves constraint type references using the type system
/// - **Constraint Application**: Associates constraints with their generic parameters
/// - **Collection Storage**: Stores processed entries in the metadata loader context
///
/// # Constraint Context
/// `GenericParamConstraint` entries are used for:
/// - **Base class constraints**: Inheritance requirements for type arguments
/// - **Interface constraints**: Implementation requirements for type arguments
/// - **Type safety**: Compile-time verification of generic usage
/// - **Optimization**: Enabling specialized code generation for constrained types
/// - **Reflection**: Runtime access to constraint information for analysis
///
/// # Errors
/// - Generic parameter references cannot be resolved
/// - Constraint type references cannot be resolved
/// - Memory allocation fails during processing
/// - Concurrent access conflicts occur
/// - Constraint application to parameters fails
///   /// # ECMA-335 Reference
///   See ECMA-335, Partition II, §22.21 for complete `GenericParamConstraint` table specification.
pub struct GenericParamConstraintLoader;

impl MetadataLoader for GenericParamConstraintLoader {
    /// Load and process all `GenericParamConstraint` table entries.
    ///
    /// This method iterates through the `GenericParamConstraint` table, resolving parameter
    /// and type references to build complete constraint structures. Each entry defines
    /// a constraint that applies to a specific generic parameter.
    ///
    /// # Returns
    /// Returns `Ok(())` on successful loading, or an error if:
    /// - Generic parameter reference resolution fails
    /// - Constraint type reference resolution fails
    /// - Raw-to-owned conversion encounters issues
    /// - Constraint application to parameters fails
    /// - Collection insertion operations fail
    /// - Parallel processing encounters errors
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let Some(header) = context.meta else {
            return Ok(());
        };
        let Some(table) = header.table::<GenericParamConstraintRaw>() else {
            return Ok(());
        };

        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row(row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("generic param constraint 0x{:08x}", row.token.value());

                let Some(res) = context.handle_result(
                    row.to_owned(&context.generic_param, context.types),
                    DiagnosticCategory::Type,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                context.handle_error(res.apply(), DiagnosticCategory::Type, token_msg)?;
                context.generic_param_constraint.insert(row.token, res);
                Ok(())
            })
    }

    /// Returns the table identifier for the `GenericParamConstraint` table.
    ///
    /// # Returns
    /// Returns [`TableId::GenericParamConstraint`] indicating this loader handles
    /// the `GenericParamConstraint` table.
    ///
    /// [`TableId::GenericParamConstraint`]: crate::prelude::TableId::GenericParamConstraint
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::GenericParamConstraint)
    }

    /// Returns the table dependencies for `GenericParamConstraint` loading.
    ///
    /// The `GenericParamConstraint` table depends on multiple tables since constraints
    /// can reference various types and must be associated with generic parameters.
    ///
    /// # Returns
    /// Returns a slice containing the required table dependencies for proper
    /// constraint resolution and parameter association.
    ///
    /// # Dependency Chain
    /// - **`GenericParam`**: Required for resolving constraint target parameters
    /// - **`TypeDef`**: Required for internal type references in constraints
    /// - **`TypeSpec`**: Required for complex type specifications in constraints
    /// - **`TypeRef`**: Required for external type references in constraints
    /// - **`MethodDef`**: Required for method-level generic parameter resolution
    /// - **`MemberRef`**: Required for member references in constraint contexts
    ///
    /// [`TableId::GenericParam`]: crate::prelude::TableId::GenericParam
    /// [`TableId::TypeDef`]: crate::prelude::TableId::TypeDef
    /// [`TableId::TypeSpec`]: crate::prelude::TableId::TypeSpec
    /// [`TableId::TypeRef`]: crate::prelude::TableId::TypeRef
    /// [`TableId::MethodDef`]: crate::prelude::TableId::MethodDef
    /// [`TableId::MemberRef`]: crate::prelude::TableId::MemberRef
    fn dependencies(&self) -> &'static [TableId] {
        &[
            TableId::GenericParam,
            TableId::TypeDef,
            TableId::TypeSpec,
            TableId::TypeRef,
            TableId::MethodDef,
            TableId::MemberRef,
        ]
    }
}

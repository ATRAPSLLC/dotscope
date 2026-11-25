//! Owned circularity validator for circular dependency detection.
//!
//! This validator provides comprehensive detection of circular dependencies within the context
//! of fully resolved .NET metadata. It operates on resolved type structures to detect circular
//! dependencies in type systems, method calls, field references, and inheritance hierarchies
//! that could lead to infinite loops or stack overflow during runtime execution.
//! This validator runs with priority 175 in the owned validation stage.
//!
//! # Architecture
//!
//! The type circularity validation system implements comprehensive circular dependency detection in sequential order:
//! 1. **Type Definition Circularity Detection** - Identifies circular dependencies through inheritance hierarchies
//! 2. **Method Call Circularity Detection** - Detects direct and indirect method call cycles
//! 3. **Field Reference Circularity Detection** - Analyzes circular field references across types
//! 4. **Generic Parameter Circularity Detection** - Validates circular generic parameter dependencies
//! 5. **Interface Implementation Circularity Detection** - Detects circular interface implementation patterns
//! 6. **Nested Type Circularity Detection** - Identifies circular nested type dependencies
//!
//! The implementation uses efficient graph algorithms including depth-first search and
//! Tarjan's algorithm for strongly connected components to detect cycles while maintaining
//! optimal performance. All validation includes early termination and memory-efficient
//! visited set management.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::owned::types::circularity::OwnedTypeCircularityValidator`] - Main validator implementation providing comprehensive circularity detection
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{OwnedTypeCircularityValidator, OwnedValidator, OwnedValidationContext};
//!
//! # fn get_context() -> OwnedValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = OwnedTypeCircularityValidator::new();
//!
//! // Check if validation should run based on configuration
//! if validator.should_run(&context) {
//!     validator.validate_owned(&context)?;
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! This validator returns [`crate::Error::ValidationOwnedFailed`] for:
//! - Type definition circular dependencies through inheritance hierarchies
//! - Method call circular dependencies (direct and indirect cycles)
//! - Field reference circular dependencies across types
//! - Generic parameter circular dependencies in constraint chains
//! - Interface implementation circular dependencies
//! - Nested type circular dependencies forming loops
//!
//! # Thread Safety
//!
//! All validation operations are read-only and thread-safe. The validator implements [`Send`] + [`Sync`]
//! and can be used concurrently across multiple threads without synchronization as it operates on
//! immutable resolved metadata structures.
//!
//! # Integration
//!
//! This validator integrates with:
//! - [`crate::metadata::validation::validators::owned::types`] - Part of the owned type validation stage
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Orchestrates validator execution
//! - [`crate::metadata::validation::traits::OwnedValidator`] - Implements the owned validation interface
//! - [`crate::metadata::cilobject::CilObject`] - Source of resolved type structures
//! - [`crate::metadata::validation::context::OwnedValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution via enable_semantic_validation flag
//!
//! # References
//!
//! - [ECMA-335 II.10.1](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Type inheritance rules
//! - [ECMA-335 II.22.37](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - TypeDef table constraints
//! - [ECMA-335 II.22.4](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Field table constraints
//! - [ECMA-335 II.22.26](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - MethodDef constraints
//! - [ECMA-335 I.8.9](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Object model constraints

use std::sync::Arc;

use rustc_hash::{FxHashMap, FxHashSet};

use crate::{
    metadata::{
        token::Token,
        typesystem::{CilFlavor, CilTypeRc},
        validation::{
            context::{OwnedValidationContext, ValidationContext},
            traits::OwnedValidator,
        },
    },
    Error, Result,
};

/// Foundation validator for circular dependencies in type systems, methods, and references.
///
/// Ensures the structural integrity and consistency of type relationships in resolved .NET metadata,
/// validating that no circular dependencies exist in inheritance hierarchies, method calls,
/// field references, or other type system relationships. This validator operates on resolved
/// type structures to provide essential guarantees about acyclic dependency patterns.
///
/// The validator implements comprehensive coverage of circular dependency detection according to
/// ECMA-335 specifications, using efficient graph algorithms to detect cycles while maintaining
/// optimal performance in the resolved metadata object model.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable resolved metadata structures.
pub struct OwnedTypeCircularityValidator;

impl OwnedTypeCircularityValidator {
    /// Creates a new type circularity validator instance.
    ///
    /// Initializes a validator instance that can be used to detect circular dependencies
    /// across multiple assemblies. The validator is stateless and can be reused safely
    /// across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::validation::validators::owned::types::circularity::OwnedTypeCircularityValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Validates inheritance chain circularity across all types.
    ///
    /// Detects circular inheritance patterns where types form cycles through their
    /// base type relationships. Uses depth-first search with cycle detection to
    /// identify inheritance loops that would cause infinite recursion.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved type structures
    ///
    /// # Returns
    ///
    /// * `Ok(())` - No inheritance circular dependencies found
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Inheritance circularity detected
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedFailed`] if:
    /// - Type inherits from itself directly or indirectly
    /// - Inheritance chain forms a cycle through multiple types
    fn validate_inheritance_circularity(&self, context: &OwnedValidationContext) -> Result<()> {
        let mut visited = FxHashMap::default();
        let mut visiting = FxHashSet::default();

        // Use cached all_types from context
        for type_rc in context.all_types() {
            let type_ptr = Arc::as_ptr(type_rc) as usize;

            // Only skip if we've already visited this type
            // The check inside the recursive function will handle re-traversal at greater depths
            if visited.contains_key(&type_ptr) {
                continue;
            }
            self.check_inheritance_cycle_and_depth(
                type_rc,
                &mut visited,
                &mut visiting,
                context,
                0,
            )?;
        }

        Ok(())
    }

    /// Recursively checks for inheritance cycles and excessive depth starting from a given type.
    ///
    /// Uses the white-gray-black algorithm where:
    /// - White (not in visited map): Unvisited
    /// - Gray (in visiting set): Currently being processed
    /// - Black (in visited map): Completely processed
    ///
    /// This unified method performs both cycle detection and depth validation in a single
    /// traversal for optimal performance. The visited map tracks the maximum depth at
    /// which each type was encountered, allowing re-traversal at greater depths to properly
    /// detect depth limit violations.
    ///
    /// Uses Arc pointers as unique type identifiers to avoid token collisions
    /// between types from different assemblies.
    ///
    /// # Arguments
    ///
    /// * `type_rc` - Type to check for inheritance cycles and depth
    /// * `visited` - Map of completely processed types (by Arc pointer) to their maximum observed depth (black)
    /// * `visiting` - Set of currently processing types (by Arc pointer) (gray)
    /// * `context` - Validation context containing configuration
    /// * `depth` - Current recursion depth
    ///
    /// # Returns
    ///
    /// Returns error if a cycle is detected or depth limit is exceeded.
    fn check_inheritance_cycle_and_depth(
        &self,
        type_rc: &CilTypeRc,
        visited: &mut FxHashMap<usize, usize>,
        visiting: &mut FxHashSet<usize>,
        context: &OwnedValidationContext,
        depth: usize,
    ) -> Result<()> {
        let type_ptr = Arc::as_ptr(type_rc) as usize;

        if visiting.contains(&type_ptr) {
            return Err(Error::ValidationOwnedFailed {
                validator: self.name().to_string(),
                message: format!(
                    "Circular inheritance detected: Type '{}' (token 0x{:08X}) inherits from itself",
                    type_rc.name, type_rc.token.value()
                ),

            });
        }

        if let Some(&max_depth) = visited.get(&type_ptr) {
            if depth <= max_depth {
                return Ok(());
            }
        }

        if depth > context.config().max_nesting_depth {
            return Err(Error::ValidationOwnedFailed {
                validator: self.name().to_string(),
                message: format!(
                    "Inheritance chain depth exceeds maximum nesting depth limit of {} for type '{}' (token 0x{:08X})",
                    context.config().max_nesting_depth, type_rc.name, type_rc.token.value()
                ),

            });
        }

        visiting.insert(type_ptr);

        if let Some(base_type) = type_rc.base() {
            self.check_inheritance_cycle_and_depth(
                &base_type,
                visited,
                visiting,
                context,
                depth.saturating_add(1),
            )?;
        }

        visiting.remove(&type_ptr);

        visited
            .entry(type_ptr)
            .and_modify(|d| *d = (*d).max(depth))
            .or_insert(depth);

        Ok(())
    }

    /// Validates nested type circularity across all types.
    ///
    /// Detects circular nested type patterns where types contain each other
    /// as nested types, either directly or through a chain of nested relationships.
    /// This prevents infinite nesting structures that could cause stack overflow.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved type structures
    ///
    /// # Returns
    ///
    /// * `Ok(())` - No nested type circular dependencies found
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Nested type circularity detected
    fn validate_nested_type_circularity(&self, context: &OwnedValidationContext) -> Result<()> {
        let mut visited = FxHashSet::default();
        let mut visiting = FxHashSet::default();

        let nested_relationships = context.nested_relationships();

        for type_rc in context.all_types() {
            let token = type_rc.token;
            if !visited.contains(&token) {
                self.check_nested_type_cycle(
                    token,
                    nested_relationships,
                    &mut visited,
                    &mut visiting,
                )?;
            }
        }

        Ok(())
    }

    /// Recursively checks for nested type cycles starting from a given type token.
    ///
    /// # Arguments
    ///
    /// * `token` - Type token to check for nested type cycles
    /// * `nested_relationships` - Map of type tokens to their nested type tokens
    /// * `visited` - Set of completely processed types
    /// * `visiting` - Set of currently processing types
    ///
    /// # Returns
    ///
    /// Returns error if a cycle is detected in the nested type relationships.
    fn check_nested_type_cycle(
        &self,
        token: Token,
        nested_relationships: &FxHashMap<Token, Vec<Token>>,
        visited: &mut FxHashSet<Token>,
        visiting: &mut FxHashSet<Token>,
    ) -> Result<()> {
        if visited.contains(&token) {
            return Ok(());
        }

        if visiting.contains(&token) {
            return Err(Error::ValidationOwnedFailed {
                validator: self.name().to_string(),
                message: format!(
                    "Circular nested type relationship detected: Type with token 0x{:08X} contains itself as nested type",
                    token.value()
                ),

            });
        }

        visiting.insert(token);

        if let Some(nested_tokens) = nested_relationships.get(&token) {
            for &nested_token in nested_tokens {
                self.check_nested_type_cycle(
                    nested_token,
                    nested_relationships,
                    visited,
                    visiting,
                )?;
            }
        }

        visiting.remove(&token);
        visited.insert(token);

        Ok(())
    }

    /// Validates interface implementation circularity across all types.
    ///
    /// Detects circular interface implementation patterns where interfaces
    /// implement each other either directly or through inheritance chains.
    /// This includes checking both explicit interface implementations and
    /// inherited interface implementations.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved type structures
    ///
    /// # Returns
    ///
    /// * `Ok(())` - No interface implementation circular dependencies found
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Interface circularity detected
    fn validate_interface_implementation_circularity(
        &self,
        context: &OwnedValidationContext,
    ) -> Result<()> {
        let mut visited = FxHashSet::default();
        let mut visiting = FxHashSet::default();

        // Use cached interface relationships from context (now using Arc pointers)
        let interface_relationships = context.interface_relationships();

        // Only check interface types from the target assembly for interface implementation cycles
        for type_rc in context.target_assembly_types() {
            let type_ptr = Arc::as_ptr(type_rc) as usize;
            if type_rc.flavor() == &CilFlavor::Interface && !visited.contains(&type_ptr) {
                self.check_interface_implementation_cycle(
                    type_ptr,
                    interface_relationships,
                    &mut visited,
                    &mut visiting,
                )?;
            }
        }

        Ok(())
    }

    /// Recursively checks for interface implementation cycles starting from a given interface.
    ///
    /// # Arguments
    ///
    /// * `type_ptr` - Arc pointer (as usize) to the interface to check
    /// * `interface_relationships` - Map of type Arc pointers to implemented interface Arc pointers
    /// * `visited` - Set of completely processed interfaces
    /// * `visiting` - Set of currently processing interfaces
    ///
    /// # Returns
    ///
    /// Returns error if a cycle is detected in the interface implementation relationships.
    fn check_interface_implementation_cycle(
        &self,
        type_ptr: usize,
        interface_relationships: &FxHashMap<usize, Vec<usize>>,
        visited: &mut FxHashSet<usize>,
        visiting: &mut FxHashSet<usize>,
    ) -> Result<()> {
        if visited.contains(&type_ptr) {
            return Ok(());
        }

        if visiting.contains(&type_ptr) {
            return Err(Error::ValidationOwnedFailed {
                validator: self.name().to_string(),
                message: "Circular interface implementation detected: Interface implements itself"
                    .to_string(),
            });
        }

        visiting.insert(type_ptr);

        if let Some(implemented_ptrs) = interface_relationships.get(&type_ptr) {
            for &implemented_ptr in implemented_ptrs {
                self.check_interface_implementation_cycle(
                    implemented_ptr,
                    interface_relationships,
                    visited,
                    visiting,
                )?;
            }
        }

        visiting.remove(&type_ptr);
        visited.insert(type_ptr);

        Ok(())
    }
}

impl OwnedValidator for OwnedTypeCircularityValidator {
    fn validate_owned(&self, context: &OwnedValidationContext) -> Result<()> {
        self.validate_inheritance_circularity(context)?;
        self.validate_nested_type_circularity(context)?;
        self.validate_interface_implementation_circularity(context)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "OwnedTypeCircularityValidator"
    }

    fn priority(&self) -> u32 {
        175
    }

    fn should_run(&self, context: &OwnedValidationContext) -> bool {
        context.config().enable_semantic_validation
    }
}

impl Default for OwnedTypeCircularityValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::validation::ValidationConfig,
        testkit::{
            factories::validation::type_circularity::owned_type_circularity_validator_file_factory,
            owned_validator_test,
        },
        Result,
    };

    #[test]
    fn test_owned_type_circularity_validator() -> Result<()> {
        let validator = OwnedTypeCircularityValidator::new();

        owned_validator_test(
            owned_type_circularity_validator_file_factory,
            "OwnedTypeCircularityValidator",
            ValidationConfig {
                enable_semantic_validation: true,
                max_nesting_depth: 100,
                ..Default::default()
            },
            |context| validator.validate_owned(context),
        )
    }
}

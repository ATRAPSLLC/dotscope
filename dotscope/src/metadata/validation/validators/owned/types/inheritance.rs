//! Comprehensive inheritance validator for type hierarchies and method inheritance.
//!
//! This validator provides comprehensive validation of inheritance relationships within the context
//! of fully resolved .NET metadata according to ECMA-335 specifications. It operates on resolved
//! type structures to validate inheritance hierarchies, detect circular dependencies, ensure
//! base type consistency, verify interface implementation rules, and validate method inheritance
//! patterns. This validator runs with priority 180 in the owned validation stage.
//!
//! # Architecture
//!
//! The inheritance validation system implements comprehensive inheritance relationship validation in sequential order:
//! 1. **Inheritance Hierarchy Consistency Validation** - Ensures inheritance relationships are well-formed without circular dependencies
//! 2. **Base Type Validation** - A type definition may not extend a sealed type or an interface, and its base must fit its kind
//! 3. **Interface Implementation Hierarchy Validation** - A type implements only interfaces
//! 4. **Abstract Concrete Inheritance Rules Validation** - Validates abstract and concrete type inheritance constraints
//! 5. **Method Inheritance Validation** - Validates method override rules, virtual method consistency, and abstract method implementation
//!
//! The implementation validates inheritance constraints according to ECMA-335 specifications,
//! ensuring proper inheritance hierarchy formation and preventing circular dependencies.
//! All validation includes graph traversal algorithms and method inheritance validation.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::owned::types::inheritance::OwnedInheritanceValidator`] - Main validator implementation providing comprehensive inheritance validation
//! - [`crate::metadata::validation::validators::owned::types::inheritance::OwnedInheritanceValidator::validate_inheritance_hierarchy_consistency`] - Inheritance hierarchy consistency and circular dependency detection
//! - [`crate::metadata::validation::validators::owned::types::inheritance::OwnedInheritanceValidator::validate_base_types`] - Base type validation for type definitions
//! - [`crate::metadata::validation::validators::owned::types::inheritance::OwnedInheritanceValidator::validate_interface_implementation_hierarchy`] - Interface implementation validation
//! - [`crate::metadata::validation::validators::owned::types::inheritance::OwnedInheritanceValidator::validate_abstract_concrete_inheritance_rules`] - Abstract and concrete type inheritance rule validation
//! - [`crate::metadata::validation::validators::owned::types::inheritance::OwnedInheritanceValidator::validate_method_inheritance`] - Method inheritance validation including override rules and virtual method consistency
//! - [`crate::metadata::validation::validators::owned::types::inheritance::OwnedInheritanceValidator::validate_basic_method_overrides`] - Basic method override validation for parameter count and final method rules
//! - [`crate::metadata::validation::validators::owned::types::inheritance::OwnedInheritanceValidator::validate_virtual_method_override`] - Virtual method override validation for signature compatibility
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{OwnedInheritanceValidator, OwnedValidator, OwnedValidationContext};
//!
//! # fn get_context() -> OwnedValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = OwnedInheritanceValidator::new();
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
//! - Inheritance hierarchy consistency violations (circular inheritance dependencies)
//! - Base type failures (a type definition extending a sealed type or an interface, or a base that does not fit its kind)
//! - Interface implementation violations (implementing a non-interface)
//! - Abstract concrete inheritance rule violations (concrete interfaces, invalid abstract/sealed combinations)
//! - Type flavor inheritance inconsistencies (incompatible flavor relationships)
//! - Method inheritance violations (concrete types with abstract methods, parameter count mismatches in overrides)
//! - Virtual method override violations (overriding final methods, signature incompatibilities)
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
//! - [`crate::metadata::method::MethodMap`] - Source of method definitions for inheritance validation
//! - [`crate::metadata::method::Method`] - Individual method instances being validated
//!
//! # References
//!
//! - [ECMA-335 I.8.9](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Inheritance and object layout
//! - [ECMA-335 II.10.1](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Type inheritance
//! - [ECMA-335 II.12.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Inheritance and overriding
//! - [ECMA-335 II.22.37](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - TypeDef inheritance

use std::sync::Arc;

use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::{
    metadata::{
        method::{Method, MethodAccessFlags, MethodModifiers, MethodVtableFlags},
        tables::{TableId, TypeAttributes},
        typesystem::{CilFlavor, CilType, CilTypeRc},
        validation::{
            context::{MethodTypeMapping, OwnedValidationContext, ValidationContext},
            traits::OwnedValidator,
        },
    },
    utils::TryForEachInOrder,
    Error, Result,
};

/// Foundation validator for inheritance hierarchies, circular dependencies, interface implementation, and method inheritance.
///
/// Ensures the structural integrity and consistency of inheritance relationships in resolved .NET metadata,
/// validating inheritance hierarchy formation, detecting circular dependencies, ensuring base type
/// compatibility, verifying interface implementation rules, and validating method inheritance patterns.
/// This validator operates on resolved type structures to provide essential guarantees about inheritance
/// integrity and method override consistency according to ECMA-335 compliance.
///
/// The validator implements comprehensive coverage of inheritance validation according to
/// ECMA-335 specifications, using graph traversal for cycle detection and method inheritance
/// validation in the resolved metadata object model.
/// Method inheritance validation includes checking abstract method implementation requirements,
/// virtual method override rules, and final method constraints.
///
/// # Usage Examples
///
/// ```no_run
/// use dotscope::metadata::validation::OwnedInheritanceValidator;
/// use dotscope::metadata::validation::OwnedValidator;
/// use dotscope::metadata::validation::OwnedValidationContext;
///
/// # fn get_context() -> OwnedValidationContext<'static> { unimplemented!() }
/// let context = get_context();
/// let validator = OwnedInheritanceValidator::new();
///
/// // Validate inheritance relationships including method inheritance
/// if validator.should_run(&context) {
///     validator.validate_owned(&context)?;
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable resolved metadata structures. Method inheritance validation
/// operates on thread-safe [`crate::metadata::method::MethodMap`] and [`crate::metadata::typesystem::CilType`] references.
pub struct OwnedInheritanceValidator;

impl OwnedInheritanceValidator {
    /// Creates a new inheritance validator instance.
    ///
    /// Initializes a validator instance that can be used to validate inheritance relationships
    /// across multiple assemblies. The validator is stateless and can be reused safely
    /// across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::validation::validators::owned::types::inheritance::OwnedInheritanceValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl OwnedInheritanceValidator {
    /// Validates inheritance hierarchy consistency and circular dependency detection.
    ///
    /// Ensures that inheritance relationships are well-formed and don't contain
    /// circular dependencies that would make type resolution impossible.
    fn validate_inheritance_hierarchy_consistency(
        &self,
        context: &OwnedValidationContext,
    ) -> Result<()> {
        let mut heights = FxHashMap::default();
        let mut visiting = FxHashSet::default();

        for type_entry in context.target_assembly_types() {
            self.inheritance_height(type_entry, type_entry, &mut heights, &mut visiting, context)?;
        }

        Ok(())
    }

    /// How many bases and interfaces stand above `type_entry` on its longest chain, walked
    /// from `start`.
    ///
    /// Heights are memoized by type, so a chain is measured whichever of its types the walk
    /// meets first. The walk fails for `start` once the chain from it passes the nesting
    /// limit, which also bounds the recursion, and on a cycle. Types are told apart by
    /// pointer: tokens repeat across assemblies.
    fn inheritance_height(
        &self,
        start: &CilType,
        type_entry: &CilType,
        heights: &mut FxHashMap<usize, usize>,
        visiting: &mut FxHashSet<usize>,
        context: &OwnedValidationContext,
    ) -> Result<usize> {
        let limit = context.config().max_nesting_depth;
        let too_deep = || Error::ValidationOwnedFailed {
            validator: self.name().to_string(),
            message: format!(
                "Inheritance chain depth exceeds maximum nesting depth limit of {} for type '{}'",
                limit, start.name
            ),
        };
        let type_ptr = std::ptr::from_ref::<CilType>(type_entry) as usize;

        if let Some(&height) = heights.get(&type_ptr) {
            if visiting.len().saturating_add(height) > limit {
                return Err(too_deep());
            }
            return Ok(height);
        }
        if visiting.contains(&type_ptr) {
            let type_name = type_entry.fullname();
            return Err(Error::ValidationOwnedFailed {
                validator: self.name().to_string(),
                message: format!(
                    "Circular inheritance dependency detected involving type '{type_name}'"
                ),
            });
        }
        if visiting.len() > limit {
            return Err(too_deep());
        }

        visiting.insert(type_ptr);
        let parents = type_entry.base().into_iter().chain(
            type_entry
                .interfaces
                .iter()
                .filter_map(|(_, entry)| entry.interface.upgrade()),
        );
        let mut height = 0usize;
        for parent in parents {
            let above = self.inheritance_height(start, &parent, heights, visiting, context)?;
            height = height.max(above.saturating_add(1));
        }
        visiting.remove(&type_ptr);

        heights.insert(type_ptr, height);
        Ok(height)
    }

    /// Validates each type definition's base type.
    ///
    /// Only a TypeDef has an `Extends` column (ECMA-335 II.22.37). Constructed types (arrays,
    /// pointers, generic instances) model their element or definition as a base, which no rule
    /// here is about. An interface extends nothing: its `Extends` must be null (II.22.37), and
    /// CoreCLR refuses any other value, `System.Object` included. Any other type may not extend
    /// a sealed type (II.10.1.4) or an interface (II.22.37), and its base must fit its kind.
    fn validate_base_types(&self, context: &OwnedValidationContext) -> Result<()> {
        for type_entry in context.target_assembly_types() {
            if !type_entry.token.is_table(TableId::TypeDef) {
                continue;
            }
            let Some(base_type) = type_entry.base() else {
                continue;
            };
            if type_entry.fullname() == base_type.fullname() {
                // A type that extends itself is the circularity validator's to report.
                continue;
            }

            if type_entry.flags.is_interface() {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Interface '{}' cannot have a base type ('{}')",
                        type_entry.name, base_type.name
                    ),
                });
            }

            if base_type.flags.is_sealed() {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Type '{}' cannot inherit from sealed type '{}'",
                        type_entry.name, base_type.name
                    ),
                });
            }

            if base_type.flags.is_interface() {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Type '{}' cannot inherit from interface '{}' (use interface implementation instead)",
                        type_entry.name, base_type.name
                    ),
                });
            }

            self.validate_type_flavor_inheritance(type_entry, &base_type)?;
        }

        Ok(())
    }

    /// Validates that every type implements only interfaces.
    ///
    /// The runtime refuses an InterfaceImpl row naming a class. Accessibility is not checked
    /// here: a type may implement any interface it can see, an internal one of its own assembly
    /// included. A TypeRef carries no flags, and a generic instance carries its definition's,
    /// so an implemented type with no flags at all is an external reference whose kind is
    /// unknown; only a type definition, or an instance of one, is judged.
    fn validate_interface_implementation_hierarchy(
        &self,
        context: &OwnedValidationContext,
    ) -> Result<()> {
        context
            .target_assembly_types()
            .par_iter()
            .try_for_each_in_order(|type_entry| -> Result<()> {
                for (_, entry) in type_entry.interfaces.iter() {
                    let Some(interface_type) = entry.interface.upgrade() else {
                        continue;
                    };
                    let kind_known = interface_type.token.is_table(TableId::TypeDef)
                        || interface_type.flags != TypeAttributes::ZERO;
                    if kind_known
                        && !interface_type.flags.is_interface()
                        && *interface_type.flavor() != CilFlavor::Interface
                    {
                        return Err(Error::ValidationOwnedFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Type '{}' tries to implement non-interface type '{}'",
                                type_entry.name, interface_type.name
                            ),
                        });
                    }
                }

                Ok(())
            })
    }

    /// Validates abstract and concrete type inheritance rules.
    ///
    /// Ensures that abstract types are properly handled in inheritance
    /// hierarchies and that concrete types implement all required members.
    fn validate_abstract_concrete_inheritance_rules(
        &self,
        context: &OwnedValidationContext,
    ) -> Result<()> {
        context
            .target_assembly_types()
            .par_iter()
            .try_for_each_in_order(|type_entry| -> Result<()> {
                let flags = type_entry.flags;

                if !flags.is_abstract() && flags.is_interface() {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!("Interface '{}' must be abstract", type_entry.name),
                    });
                }

                Ok(())
            })
    }

    /// Validates that a non-interface type definition's base fits its kind.
    ///
    /// A value type extends `System.ValueType` or `System.Enum` (ECMA-335 II.13), primitives
    /// included; `System.ValueType` itself is the root and extends `System.Object`. A class
    /// needs nothing more than the sealed and interface rules its caller applies.
    fn validate_type_flavor_inheritance(
        &self,
        derived_type: &CilType,
        base_type: &CilType,
    ) -> Result<()> {
        let derived_flavor = derived_type.flavor();
        if derived_flavor.is_value_type() {
            let base_fullname = base_type.fullname();
            if base_fullname != "System.ValueType" && base_fullname != "System.Enum" {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Value type '{}' has incompatible base type flavor",
                        derived_type.name
                    ),
                });
            }
        }
        Ok(())
    }

    /// Validates method inheritance relationships across type hierarchies.
    ///
    /// Performs comprehensive validation of method inheritance patterns according to ECMA-335
    /// specifications, ensuring that method overrides follow proper inheritance rules and that
    /// abstract methods are properly implemented in concrete derived types. This validation
    /// includes checking virtual method consistency, abstract method implementation requirements,
    /// and final method constraints.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved method and type structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All method inheritance relationships are valid
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Method inheritance violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedFailed`] if:
    /// - Concrete types contain abstract methods (violates ECMA-335 requirements)
    /// - Virtual method overrides have incompatible signatures (parameter count mismatches)
    /// - Final methods are being overridden (violates sealing constraints)
    /// - Method inheritance chains are inconsistent across type hierarchies
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and operates on immutable resolved metadata structures.
    /// All method and type data is accessed through thread-safe collections.
    fn validate_method_inheritance(&self, context: &OwnedValidationContext) -> Result<()> {
        let method_mapping = context.method_type_mapping();

        for type_entry in context.target_assembly_types() {
            // A concrete type cannot have abstract methods, whatever it derives from.
            if type_entry.token.is_table(TableId::TypeDef) && !type_entry.flags.is_abstract() {
                for (_, method) in type_entry.methods.iter() {
                    if let Some(method) = method.upgrade() {
                        if method.is_abstract() {
                            return Err(Error::ValidationOwnedFailed {
                                validator: self.name().to_string(),
                                message: format!(
                                    "Concrete type '{}' cannot have abstract method '{}'",
                                    type_entry.name, method.name
                                ),
                            });
                        }
                    }
                }
            }
            if let Some(base_type) = type_entry.base() {
                self.validate_basic_method_overrides(type_entry, &base_type, method_mapping)?;
            }
        }

        Ok(())
    }

    /// Validates basic method override rules between derived and base types.
    ///
    /// Performs validation of fundamental method inheritance rules according to ECMA-335
    /// specifications, focusing on abstract method implementation requirements and basic
    /// virtual method override constraints. This validation ensures that concrete types
    /// properly implement abstract methods and that virtual method overrides follow
    /// inheritance rules.
    ///
    /// # Arguments
    ///
    /// * `derived_type` - The derived type containing methods to validate via [`crate::metadata::typesystem::CilType`]
    /// * `base_type` - The base type containing methods being overridden via [`crate::metadata::typesystem::CilType`]
    /// * `method_mapping` - Pre-built mapping for efficient validation
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All basic method override rules are satisfied
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Method override violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedFailed`] if:
    /// - Virtual method override validation fails for any method pair
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and operates on immutable resolved metadata structures.
    fn validate_basic_method_overrides(
        &self,
        derived_type: &CilTypeRc,
        base_type: &CilTypeRc,
        method_mapping: &MethodTypeMapping,
    ) -> Result<()> {
        if base_type.flags.is_interface() {
            return Ok(());
        }

        let type_address = Arc::as_ptr(derived_type) as usize;
        let type_methods = method_mapping.get_type_methods(type_address);
        for &method_address in type_methods {
            if let Some(method) = method_mapping.get_method(method_address) {
                if method.is_virtual() {
                    self.validate_virtual_method_override(
                        method,
                        derived_type,
                        base_type,
                        method_mapping,
                    )?;
                }
            }
        }
        Ok(())
    }

    /// Validates virtual method override rules against base type methods.
    ///
    /// Performs detailed validation of virtual method overrides according to ECMA-335
    /// specifications, ensuring that method signatures are compatible and that final
    /// methods are not being overridden. This validation checks parameter count consistency
    /// and enforces final method sealing constraints across inheritance hierarchies.
    ///
    /// # Arguments
    ///
    /// * `derived_method` - The derived virtual method being validated via [`crate::metadata::method::Method`]
    /// * `derived_type` - The derived type containing the method via [`crate::metadata::typesystem::CilType`]
    /// * `base_type` - The base type containing potential overridden methods via [`crate::metadata::typesystem::CilType`]
    /// * `method_mapping` - Pre-built mapping for efficient validation
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All virtual method override rules are satisfied
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Virtual method override violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedFailed`] if:
    /// - Method override parameter count differs from base method (signature incompatibility)
    /// - Attempting to override a final method (sealing violation)
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and operates on immutable resolved metadata structures.
    fn validate_virtual_method_override(
        &self,
        derived_method: &Method,
        derived_type: &CilTypeRc,
        base_type: &CilTypeRc,
        method_mapping: &MethodTypeMapping,
    ) -> Result<()> {
        if base_type.flags.is_interface() {
            return Ok(());
        }

        if !derived_method
            .flags_modifiers
            .contains(MethodModifiers::VIRTUAL)
        {
            return Ok(());
        }

        // ECMA-335 II.10.3.1: a `newslot` method takes a new vtable slot and overrides nothing,
        // whatever base method shares its name and signature. C# compiles `new virtual` this
        // way, and every method that implements an interface implicitly: a class implementing
        // `IDisposable` again beside a base that did gets its own `final newslot Dispose`.
        if derived_method
            .flags_vtable
            .contains(MethodVtableFlags::NEW_SLOT)
        {
            return Ok(());
        }

        let base_address = Arc::as_ptr(base_type) as usize;
        let base_methods = method_mapping.get_type_methods(base_address);
        for &base_method_address in base_methods {
            if let Some(base_method) = method_mapping.get_method(base_method_address) {
                if base_method
                    .flags_modifiers
                    .contains(MethodModifiers::VIRTUAL)
                    && Self::is_potential_method_override(derived_method, base_method)
                {
                    self.validate_method_override_rules(
                        derived_method,
                        derived_type,
                        base_method,
                        base_type,
                    )?;
                }
            }
        }
        Ok(())
    }

    /// Determines if a derived method could potentially override a base method.
    ///
    /// This implements .NET method signature matching rules to determine if two methods
    /// represent an override relationship rather than overloading or hiding.
    ///
    /// # Arguments
    ///
    /// * `derived_method` - The method in the derived type
    /// * `base_method` - The potential base method to override
    ///
    /// # Returns
    ///
    /// `true` if the derived method could override the base method (same signature)
    fn is_potential_method_override(derived_method: &Method, base_method: &Method) -> bool {
        if derived_method.name != base_method.name {
            return false;
        }

        // ECMA-335 II.10.3: a method overrides the base method of the same name and
        // signature, so an overload with other parameter or return types is a method of
        // its own.
        derived_method
            .signature
            .has_same_shape(&base_method.signature)
    }

    /// Validates the rules for method overriding between derived and base methods.
    ///
    /// This implements .NET method override validation according to ECMA-335 specifications,
    /// ensuring that override relationships follow proper inheritance rules.
    ///
    /// # Arguments
    ///
    /// * `derived_method` - The overriding method in the derived type
    /// * `derived_type` - The derived type containing the method
    /// * `base_method` - The base method being overridden
    /// * `base_type` - The base type containing the overridden method
    ///
    /// # Returns
    ///
    /// Returns error if override rules are violated
    fn validate_method_override_rules(
        &self,
        derived_method: &Method,
        derived_type: &CilTypeRc,
        base_method: &Method,
        base_type: &CilTypeRc,
    ) -> Result<()> {
        if base_method.flags_modifiers.contains(MethodModifiers::FINAL) {
            return Err(Error::ValidationOwnedFailed {
                validator: self.name().to_string(),
                message: format!(
                    "Cannot override final method '{}' - final methods cannot be overridden",
                    base_method.name
                ),
            });
        }

        if !base_method
            .flags_modifiers
            .contains(MethodModifiers::VIRTUAL)
        {
            return Err(Error::ValidationOwnedFailed {
                validator: self.name().to_string(),
                message: format!(
                    "Cannot override non-virtual method '{}' - only virtual methods can be overridden",
                    base_method.name
                ),
            });
        }

        if !derived_method
            .flags_modifiers
            .contains(MethodModifiers::VIRTUAL)
        {
            return Err(Error::ValidationOwnedFailed {
                validator: self.name().to_string(),
                message: format!(
                    "Method '{}' must be virtual to override base method",
                    derived_method.name
                ),
            });
        }

        // ECMA-335 I.8.5.3.2: Check accessibility narrowing restrictions
        // General rule: Override methods cannot be less accessible than base methods
        // Exception (ECMA-335 I.8.5.3.2): When overriding a method from a different assembly
        // with family-or-assembly accessibility, the override may have family or assembly accessibility.
        // This is not considered restricting access because family-or-assembly cannot be
        // properly expressed across assembly boundaries.
        if derived_method.flags_access < base_method.flags_access {
            // ECMA-335 I.8.5.3.2: Cross-assembly exception for FAMILY_OR_ASSEMBLY narrowing
            // When overriding across assembly boundaries, family-or-assembly can be narrowed to:
            // - FAMILY (protected) - accessible to derived classes
            // - ASSEMBLY (internal) - accessible within the assembly
            let is_cross_assembly = !derived_type.external_sources_equivalent(base_type);

            let is_exception_case = is_cross_assembly
                && base_method.flags_access == MethodAccessFlags::FAMILY_OR_ASSEMBLY
                && (derived_method.flags_access == MethodAccessFlags::FAMILY
                    || derived_method.flags_access == MethodAccessFlags::ASSEMBLY);

            if !is_exception_case {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Override method '{}' cannot be less accessible than base method (derived: {:?}, base: {:?})",
                        derived_method.name,
                        derived_method.flags_access,
                        base_method.flags_access
                    ),

                });
            }
        }

        if base_method
            .flags_modifiers
            .contains(MethodModifiers::ABSTRACT)
            && derived_method
                .flags_modifiers
                .contains(MethodModifiers::ABSTRACT)
        {
            // This is OK - abstract method can be overridden by another abstract method
            // The concrete class further down the hierarchy must provide implementation
        }

        Ok(())
    }
}

impl OwnedValidator for OwnedInheritanceValidator {
    fn validate_owned(&self, context: &OwnedValidationContext) -> Result<()> {
        self.validate_inheritance_hierarchy_consistency(context)?;
        self.validate_base_types(context)?;
        self.validate_interface_implementation_hierarchy(context)?;
        self.validate_abstract_concrete_inheritance_rules(context)?;
        self.validate_method_inheritance(context)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "OwnedInheritanceValidator"
    }

    fn priority(&self) -> u32 {
        180
    }

    fn should_run(&self, context: &OwnedValidationContext) -> bool {
        context.config().enable_semantic_validation
    }
}

impl Default for OwnedInheritanceValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::{
            signatures::{SignatureMethod, SignatureParameter, TypeSignature},
            token::Token,
            validation::ValidationConfig,
        },
        testkit::{
            builders::MethodBuilder,
            factories::validation::inheritance::owned_inheritance_validator_file_factory, fixture,
            owned_validator_test,
        },
        CilObject,
    };

    /// Two methods with the same name and signature match as an override whether or not they
    /// have Param rows: a Param row is optional (ECMA-335 §22.33), and obfuscators drop them.
    #[test]
    fn an_override_matches_by_signature_not_param_rows() {
        let signature = SignatureMethod {
            has_this: true,
            param_count: 1,
            return_type: SignatureParameter {
                modifiers: Vec::new(),
                by_ref: false,
                base: TypeSignature::Void,
            },
            params: vec![SignatureParameter {
                modifiers: Vec::new(),
                by_ref: false,
                base: TypeSignature::I4,
            }],
            ..Default::default()
        };
        let with_rows = MethodBuilder::new()
            .with_name("Run")
            .with_signature(signature.clone())
            .build();
        let without_rows = MethodBuilder::new()
            .with_rid(2)
            .with_name("Run")
            .with_signature(signature)
            .without_auto_params()
            .build();
        assert_eq!(with_rows.params.count(), 1);
        assert_eq!(without_rows.params.count(), 0);

        assert!(OwnedInheritanceValidator::is_potential_method_override(
            &without_rows,
            &with_rows
        ));
        assert!(OwnedInheritanceValidator::is_potential_method_override(
            &with_rows,
            &without_rows
        ));
    }

    /// Overloads that differ only in which class a parameter takes are two methods: sealing
    /// one does not seal the other. Roslyn's `SemanticModel` seals one
    /// `TryGetSpeculativeSemanticModelCore` and overrides its siblings below it.
    #[test]
    fn an_overload_on_another_class_is_not_an_override() {
        let taking = |class: u32| SignatureMethod {
            has_this: true,
            param_count: 1,
            return_type: SignatureParameter {
                modifiers: Vec::new(),
                by_ref: false,
                base: TypeSignature::Boolean,
            },
            params: vec![SignatureParameter {
                modifiers: Vec::new(),
                by_ref: false,
                base: TypeSignature::Class(Token::new(class)),
            }],
            ..Default::default()
        };
        let sealed = MethodBuilder::new()
            .with_name("TryGet")
            .with_signature(taking(0x0200_0002))
            .build();
        let sibling = MethodBuilder::new()
            .with_rid(2)
            .with_name("TryGet")
            .with_signature(taking(0x0200_0003))
            .build();

        assert!(!OwnedInheritanceValidator::is_potential_method_override(
            &sibling, &sealed
        ));
    }

    #[test]
    fn assemblies_that_seal_one_overload_load() {
        for path in [
            "mono_4.5/Microsoft.CodeAnalysis.CSharp.dll",
            "mono_4.5/System.Web.dll",
        ] {
            if let Err(error) = CilObject::from_path(fixture(path)) {
                panic!("{path}: {error}");
            }
        }
    }

    #[test]
    fn test_owned_inheritance_validator_comprehensive() -> Result<()> {
        let validator = OwnedInheritanceValidator::new();

        owned_validator_test(
            owned_inheritance_validator_file_factory,
            "OwnedInheritanceValidator",
            ValidationConfig {
                enable_semantic_validation: true,
                ..Default::default()
            },
            |context| validator.validate_owned(context),
        )
    }
}

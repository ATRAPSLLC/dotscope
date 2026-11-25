//! Type resolution, compatibility checking, and size computation for the emulation context.
//!
//! Provides type lookup, inheritance-based compatibility, virtual method dispatch,
//! field type inspection, and type size calculations.

use crate::{
    emulation::engine::{context::EmulationContext, error::EmulationError, exceptions},
    metadata::{
        method::Method,
        streams::SharedStr,
        tables::TableId,
        token::Token,
        typesystem::{CilFlavor, CilType, CilTypeRc, PointerSize},
    },
    Result,
};

/// Deepest inheritance chain the override lookup will follow.
const MAX_BASE_WALK_DEPTH: usize = 256;

impl EmulationContext {
    /// Converts a type token to a CilFlavor.
    ///
    /// This handles TypeDef, TypeRef, and TypeSpec tokens, resolving them
    /// to the appropriate CIL flavor type for emulation.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::UnresolvedTypeToken`] if the type cannot be resolved
    /// and the token table is not a recognized type table.
    pub fn type_token_to_cil_flavor(&self, token: Token) -> Result<CilFlavor> {
        if let Some(cil_type) = self.assembly.types().get(&token) {
            return Ok(cil_type.flavor().clone());
        }

        Err(EmulationError::UnresolvedTypeToken { token }.into())
    }

    /// Gets a type by its token.
    ///
    /// Returns the [`CilType`] for the given token if it exists in the
    /// assembly's type registry.
    ///
    /// # Returns
    ///
    /// `Some(CilTypeRc)` if the type is found, `None` otherwise.
    #[must_use]
    pub fn get_type(&self, type_token: Token) -> Option<CilTypeRc> {
        self.assembly.types().get(&type_token)
    }

    /// Gets a type by namespace and name.
    ///
    /// Searches the assembly's type registry for a type with the given
    /// qualified name.
    ///
    /// # Returns
    ///
    /// `Some(CilTypeRc)` if the type is found, `None` otherwise.
    #[must_use]
    pub fn get_type_by_name(&self, namespace: &str, name: &str) -> Option<CilTypeRc> {
        let fullname = if namespace.is_empty() {
            name.to_string()
        } else {
            format!("{namespace}.{name}")
        };
        self.assembly.types().get_by_fullname(&fullname, true)
    }

    /// Checks if one type is compatible with (assignable to) another.
    ///
    /// This uses the full .NET type compatibility rules including:
    /// - Exact type matching
    /// - Inheritance compatibility (subtype checking)
    /// - Interface implementation
    /// - Primitive type widening
    /// - Reference types to System.Object
    ///
    /// # Arguments
    ///
    /// * `source_token` - Token of the source type (the value's type)
    /// * `target_token` - Token of the target type (the expected type)
    ///
    /// # Returns
    ///
    /// `true` if the source type can be assigned to the target type.
    /// Returns `true` if either type cannot be resolved (permissive fallback).
    #[must_use]
    pub fn is_type_compatible(&self, source_token: Token, target_token: Token) -> bool {
        // Same token is always compatible
        if source_token == target_token {
            return true;
        }

        // Synthetic exception tokens have an explicit hierarchy — use it.
        if exceptions::is_synthetic(source_token) {
            if exceptions::is_synthetic(target_token) {
                return exceptions::is_subtype_of(source_token, target_token);
            }
            // Target is a real type — try to map it to a synthetic token for comparison.
            // This handles catch clauses that reference the BCL type (e.g. TypeRef for
            // System.Exception) when the thrown exception uses a synthetic token.
            if let Some(target_type) = self.get_type(target_token) {
                let fullname = target_type.fullname();
                if let Some(synthetic_target) = exceptions::token_from_fullname(&fullname) {
                    return exceptions::is_subtype_of(source_token, synthetic_target);
                }
            }
            // Target is an unknown external BCL type — permissive fallback
            return true;
        }

        // Source is a real type, target is synthetic — map source to synthetic if possible
        if exceptions::is_synthetic(target_token) {
            if let Some(source_type) = self.get_type(source_token) {
                let fullname = source_type.fullname();
                if let Some(synthetic_source) = exceptions::token_from_fullname(&fullname) {
                    return exceptions::is_subtype_of(synthetic_source, target_token);
                }
            }
            // Source is unknown — permissive fallback
            return true;
        }

        // Both are real types — try to resolve
        let Some(source_type) = self.get_type(source_token) else {
            // Source type cannot be resolved from metadata. If it's a synthetic
            // BCL wrapper token (Stream, Encoding, etc.) and the target IS a
            // resolvable TypeDef, BCL wrapper types never extend user-defined
            // classes. Without this check, castclass on a BCL wrapper against a
            // user type silently succeeds, masking CFF branch errors (e.g., a
            // Stream passing castclass for an abstract user class, preventing the
            // expected InvalidCastException that CFF exception handlers rely on).
            if is_bcl_wrapper_token(source_token) && target_token.is_table(TableId::TypeDef) {
                if let Some(target_type) = self.get_type(target_token) {
                    let name = target_type.fullname();
                    if &*name == "System.Object" || &*name == "System.ValueType" {
                        return true;
                    }
                    if target_type.is_interface() {
                        return true;
                    }
                    return false;
                }
            }
            return true; // Fully unknown — permissive
        };

        let Some(target_type) = self.get_type(target_token) else {
            return true; // Permissive if target type unknown
        };

        // Use CilType's is_compatible_with method
        source_type.is_compatible_with(&target_type)
    }

    /// Checks if a type is compatible with another type using CilType references.
    ///
    /// This is a convenience method that takes resolved CilType references
    /// instead of tokens.
    #[must_use]
    pub fn is_type_compatible_ref(source: &CilType, target: &CilType) -> bool {
        source.is_compatible_with(target)
    }

    /// Returns the declaring type token and field type flavor for a field.
    ///
    /// Combines [`declaring_type_of_field()`](crate::metadata::resolver::TokenResolver::declaring_type_of_field)
    /// with field signature inspection. Used by `handle_ldsfld` to return the
    /// correct zero-initialized default value for fields on initialized types.
    ///
    /// # Arguments
    ///
    /// * `field_token` - A FieldDef token (table 0x04).
    ///
    /// # Returns
    ///
    /// * `Some((type_token, cil_flavor))` - The declaring type token and the field's type flavor
    /// * `None` - The field could not be found
    #[must_use]
    pub fn get_field_type_info(&self, field_token: Token) -> Option<(Token, CilFlavor)> {
        let declaring_type = self
            .assembly
            .resolver()
            .declaring_type_of_field(field_token)?;
        // Find the field in the type to get its signature
        for (_, field_rc) in declaring_type.fields.iter() {
            if field_rc.token == field_token {
                let flavor = CilFlavor::from(&field_rc.signature.base);
                return Some((declaring_type.token, flavor));
            }
        }
        None
    }

    /// Finds the static constructor (.cctor) for a type.
    ///
    /// The static constructor is a special method named ".cctor" that is
    /// called automatically by the runtime before any static member of
    /// the type is accessed.
    ///
    /// # Arguments
    ///
    /// * `type_token` - Token of the type to find the .cctor for
    ///
    /// # Returns
    ///
    /// `Some(Token)` if the type has a static constructor, `None` otherwise.
    #[must_use]
    pub fn find_type_cctor(&self, type_token: Token) -> Option<Token> {
        let type_info = self.assembly.types().get(&type_token)?;
        let result = type_info
            .query_methods()
            .static_constructors()
            .find_first()
            .map(|m| m.token);
        result
    }

    /// Returns the token of the base type for the given type, if any.
    ///
    /// Used for base-type-first initialization ordering (ECMA-335 §II.10.5.3).
    #[must_use]
    pub fn get_base_type_token(&self, type_token: Token) -> Option<Token> {
        let type_info = self.assembly.types().resolve(&type_token)?;
        type_info.base().map(|b| b.token)
    }

    /// Checks if a method is virtual.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::MethodNotFound`] if the method is not found.
    pub fn is_virtual_method(&self, method_token: Token) -> Result<bool> {
        let method = self.get_method(method_token)?;
        Ok(method.is_virtual())
    }

    /// Resolves a virtual method call to a concrete implementation.
    ///
    /// Given a virtual method token and the runtime type of the object,
    /// this resolves to the actual method that should be called based on
    /// the type hierarchy. The runtime type is resolved via
    /// [`TypeRegistry::resolve()`](crate::metadata::typesystem::TypeRegistry::resolve),
    /// so TypeRef runtime types (e.g., from the heap) are automatically
    /// normalized to TypeDefs with populated method lists.
    ///
    /// # Arguments
    ///
    /// * `method_token` - The declared virtual method being called
    /// * `runtime_type` - The actual runtime type of the object (may be TypeRef or TypeDef)
    ///
    /// # Returns
    ///
    /// The token of the method to actually call. If virtual dispatch cannot
    /// be resolved (type unknown, method not overridden), returns the original
    /// method token.
    #[must_use]
    pub fn resolve_virtual_call(&self, method_token: Token, runtime_type: Token) -> Token {
        // Get the method being called
        let Ok(method) = self.get_method(method_token) else {
            return method_token;
        };

        // Not virtual? Return as-is
        if !method.is_virtual() {
            return method_token;
        }

        let method_name = &method.name;

        // Get the runtime type (resolve TypeRef→TypeDef so we get methods/fields)
        let Some(runtime_type_info) = self.assembly.types().resolve(&runtime_type) else {
            return method_token;
        };

        // Search for an override in the runtime type
        if let Some(override_token) =
            Self::find_method_override(0, &runtime_type_info, method_name, &method)
        {
            return override_token;
        }

        // No override found, return original
        method_token
    }

    /// Finds a method override in a type hierarchy.
    ///
    /// Searches for a virtual method override that matches both the name and
    /// signature of the base method. This ensures proper override resolution
    /// and avoids matching methods that merely hide the base method.
    fn find_method_override(
        depth: usize,
        type_info: &CilType,
        method_name: &str,
        base_method: &Method,
    ) -> Option<Token> {
        // Tail-recurses down `base()`, which may be cyclic — `set_base` allows
        // that by design so the circularity validator can report it.
        if depth >= MAX_BASE_WALK_DEPTH {
            return None;
        }
        // First check the type itself for a matching override
        if let Some(method) = type_info
            .query_methods()
            .virtual_methods()
            .name(method_name)
            .filter(|m| m.signature.has_same_parameters(&base_method.signature))
            .find_first()
        {
            return Some(method.token);
        }

        // Check base types (inheritance chain)
        if let Some(base) = type_info.base() {
            return Self::find_method_override(
                depth.saturating_add(1),
                &base,
                method_name,
                base_method,
            );
        }

        None
    }

    /// Gets type information useful for casting operations.
    ///
    /// Returns the type's namespace and name, which is useful for
    /// error messages in cast failures.
    #[must_use]
    pub fn get_type_name(&self, type_token: Token) -> Option<(SharedStr, SharedStr)> {
        self.get_type(type_token)
            .map(|t| (t.namespace.clone(), t.name.clone()))
    }

    /// Formats a type token as a readable string for error messages.
    ///
    /// Returns "Namespace.Name" if the type is known, or "0x{token:08X}"
    /// if the type cannot be resolved.
    #[must_use]
    pub fn format_type_token(&self, type_token: Token) -> String {
        if let Some(type_info) = self.get_type(type_token) {
            type_info.fullname().to_string()
        } else {
            format!("0x{:08X}", type_token.value())
        }
    }

    /// Checks if a type is a value type.
    ///
    /// Value types (structs, enums, primitives) are copied by value
    /// rather than by reference.
    #[must_use]
    pub fn is_value_type(&self, type_token: Token) -> bool {
        self.get_type(type_token).is_some_and(|t| t.is_value_type())
    }

    /// Checks if a type is a reference type.
    ///
    /// Reference types (classes, interfaces, arrays) are passed by reference.
    #[must_use]
    pub fn is_reference_type(&self, type_token: Token) -> bool {
        self.get_type(type_token)
            .is_none_or(|t| t.flavor().is_reference_type()) // Default to reference type if unknown
    }

    /// Checks if a type is an interface.
    #[must_use]
    pub fn is_interface(&self, type_token: Token) -> bool {
        self.get_type(type_token).is_some_and(|t| t.is_interface())
    }

    /// Gets the size of a type in bytes for the sizeof instruction.
    ///
    /// This method computes the size based on:
    /// 1. Explicit `ClassLayout.class_size` if defined for the type
    /// 2. Primitive type sizes based on the `CilFlavor`
    /// 3. A default pointer-sized value for unknown types
    ///
    /// # Arguments
    ///
    /// * `type_token` - Token of the type to get size for
    /// * `ptr_size` - Target pointer size for native int/uint types
    ///
    /// # Returns
    ///
    /// The size of the type in bytes.
    #[must_use]
    pub fn get_type_size(&self, type_token: Token, ptr_size: PointerSize) -> usize {
        // Try to get the type from the registry
        if let Some(cil_type) = self.get_type(type_token) {
            // First check for explicit ClassLayout size
            if let Some(&explicit_size) = cil_type.class_size.get() {
                return explicit_size as usize;
            }

            // Otherwise compute from the flavor
            return cil_type
                .flavor()
                .byte_size(ptr_size)
                .unwrap_or(ptr_size.bytes());
        }

        // Default size for unknown types (pointer-sized)
        ptr_size.bytes()
    }
}

/// Returns `true` if the token is a synthetic BCL wrapper type token (`0x7F00_xxxx`).
///
/// These tokens are assigned by the heap to objects that have no real .NET type
/// identity — BCL wrapper types like `Stream`, `Encoding`, `CryptoAlgorithm`,
/// `Dictionary`, etc. They use the non-existent metadata table `0x7F` to avoid
/// collision with real TypeDef/TypeRef/TypeSpec tokens.
///
/// Distinct from synthetic exception tokens (`0x7F01_00xx`) which have their own
/// hierarchy in [`exceptions`].
fn is_bcl_wrapper_token(token: Token) -> bool {
    token.value() & 0xFFFF_0000 == 0x7F00_0000
}

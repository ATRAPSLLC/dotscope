//! Type signature hashing for deduplication and identity comparison.
//!
//! This module provides the `TypeSignatureHash` for computing collision-resistant
//! hashes of type signatures, enabling effective deduplication of types in the
//! type registry. The hash function uses FNV-1a inspired sequential mixing to
//! avoid the collision problems of XOR-based combination.
//!
//! # Hash Design
//!
//! The hash function incorporates all distinguishing characteristics of a type:
//! - **Flavor**: The fundamental type category (Class, Interface, GenericInstance, etc.)
//! - **Identity**: Full namespace and name
//! - **Source**: Assembly/module origin
//! - **Context**: Generic arguments, base types, and other structural information
//!
//! # Example Usage
//!
//! ```
//! use dotscope::metadata::typesystem::TypeSignatureHash;
//! use dotscope::metadata::typesystem::{CilFlavor, TypeSource};
//! use dotscope::metadata::token::Token;
//!
//! // The generic argument: `System.String`, as the module's TypeRef names it
//! let string_token = Token::new(0x0100_0002);
//!
//! let hash = TypeSignatureHash::new()
//!     .add_flavor(&CilFlavor::GenericInstance)
//!     .add_fullname("System.Collections.Generic", "List`1")
//!     .add_source(&TypeSource::Primitive)
//!     .add_component(&string_token)  // Generic argument
//!     .finalize();
//! ```

use std::hash::{DefaultHasher, Hash, Hasher};

use crate::metadata::{
    token::Token,
    typesystem::{CilFlavor, TypeSource},
};

/// High-quality hash builder for type signatures using FNV-1a inspired mixing
///
/// This hash function solves the collision problems of XOR-based approaches by using
/// sequential mixing with multiplication. Each component is mixed into the hash state
/// in a way that preserves order and prevents self-cancellation.
pub struct TypeSignatureHash {
    /// Current hash state using FNV-1a algorithm principles
    state: u64,
}

impl TypeSignatureHash {
    /// Create a new signature hash builder
    ///
    /// Initializes with FNV-1a offset basis for good hash distribution
    #[must_use]
    pub fn new() -> Self {
        TypeSignatureHash {
            state: 0xcbf2_9ce4_8422_2325_u64, // FNV-1a 64-bit offset basis
        }
    }

    /// Mix a 64-bit value into the hash state using enhanced algorithm with better avalanche
    ///
    /// This uses a combination of FNV-1a and additional mixing for better collision resistance
    fn mix(&mut self, value: u64) {
        self.state ^= value;
        self.state = self.state.wrapping_mul(0x0100_0000_01b3_u64); // FNV-1a 64-bit prime

        // Additional mixing for better avalanche properties
        self.state ^= self.state >> 33;
        self.state = self.state.wrapping_mul(0xff51_afd7_ed55_8ccd_u64);
        self.state ^= self.state >> 33;
    }

    /// Add a hashable component to the signature
    ///
    /// This method can hash any type that implements the `Hash` trait, providing
    /// flexibility for including various type information in the signature.
    ///
    /// ## Arguments
    /// * `component` - Any hashable component to include in the signature
    #[must_use]
    pub fn add_component<T: Hash + ?Sized>(mut self, component: &T) -> Self {
        let mut hasher = DefaultHasher::new();
        component.hash(&mut hasher);
        self.mix(hasher.finish());
        self
    }

    /// Add the type flavor to the signature
    ///
    /// The flavor distinguishes fundamental type categories and prevents
    /// collisions between types with the same name but different categories
    /// (e.g., `List` class vs `List<T>` generic instance).
    ///
    /// ## Arguments  
    /// * `flavor` - The CIL flavor/category of the type
    #[must_use]
    pub fn add_flavor(self, flavor: &CilFlavor) -> Self {
        self.add_component(flavor)
    }

    /// Add the full type name (namespace + name) to the signature
    ///
    /// ## Arguments
    /// * `namespace` - The type's namespace (may be empty for global types)
    /// * `name` - The type's name including generic arity markers (e.g., "List`1")
    #[must_use]
    pub fn add_fullname(self, namespace: &str, name: &str) -> Self {
        self.add_component(namespace).add_component(name)
    }

    /// Add the type source information to the signature
    ///
    /// This distinguishes types from different assemblies, modules, or files
    /// that might otherwise have identical names and structures.
    ///
    /// ## Arguments
    /// * `source` - The source context where the type is defined
    #[must_use]
    pub fn add_source(self, source: &TypeSource) -> Self {
        self.add_component(source)
    }

    /// Add a token to the signature
    ///
    /// Tokens are the primary way to identify types, methods, and other metadata
    /// entities. This method provides efficient hashing of token values.
    ///
    /// ## Arguments
    /// * `token` - The metadata token to include in the signature
    #[must_use]
    pub fn add_token(self, token: &Token) -> Self {
        self.add_component(&token.value())
    }

    /// Finalize the hash and return the computed signature
    ///
    /// ## Returns
    /// A 64-bit hash value representing the complete type signature
    #[must_use]
    pub fn finalize(self) -> u64 {
        self.state
    }
}

impl Default for TypeSignatureHash {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::typesystem::CilFlavor;

    #[test]
    fn test_hash_deterministic() {
        let hash1 = TypeSignatureHash::new()
            .add_flavor(&CilFlavor::Class)
            .add_fullname("System", "String")
            .add_source(&TypeSource::Unknown)
            .finalize();

        let hash2 = TypeSignatureHash::new()
            .add_flavor(&CilFlavor::Class)
            .add_fullname("System", "String")
            .add_source(&TypeSource::Unknown)
            .finalize();

        assert_eq!(hash1, hash2, "Hash should be deterministic");
    }

    #[test]
    fn test_hash_order_sensitive() {
        let hash1 = TypeSignatureHash::new()
            .add_component(&"first")
            .add_component(&"second")
            .finalize();

        let hash2 = TypeSignatureHash::new()
            .add_component(&"second")
            .add_component(&"first")
            .finalize();

        assert_ne!(hash1, hash2, "Hash should be order-sensitive");
    }

    #[test]
    fn test_flavor_differentiation() {
        let class_hash = TypeSignatureHash::new()
            .add_flavor(&CilFlavor::Class)
            .add_fullname("System.Collections.Generic", "List`1")
            .finalize();

        let generic_hash = TypeSignatureHash::new()
            .add_flavor(&CilFlavor::GenericInstance)
            .add_fullname("System.Collections.Generic", "List`1")
            .finalize();

        assert_ne!(
            class_hash, generic_hash,
            "Different flavors should produce different hashes"
        );
    }

    #[test]
    fn test_collision_resistance() {
        // Test that similar but different types produce different hashes
        let test_cases = vec![
            ("System", "String"),
            ("System", "Object"),
            ("System.Collections", "String"),
            ("System", "StringBuilder"),
        ];

        let mut hashes = Vec::new();
        for (namespace, name) in test_cases {
            let hash = TypeSignatureHash::new()
                .add_flavor(&CilFlavor::Class)
                .add_fullname(namespace, name)
                .add_source(&TypeSource::Unknown)
                .finalize();
            hashes.push(hash);
        }

        // Check that all hashes are unique
        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                assert_ne!(
                    hashes[i], hashes[j],
                    "Similar types should have different hashes"
                );
            }
        }
    }
}

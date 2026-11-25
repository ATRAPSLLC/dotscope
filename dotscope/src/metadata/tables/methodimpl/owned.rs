//! Owned `MethodImpl` table structure with resolved references and implementation mappings.
//!
//! This module provides the [`MethodImpl`] struct, which represents method implementation
//! mappings with all coded indexes resolved and type references established. Unlike
//! [`MethodImplRaw`], this structure contains resolved class and method references
//! enabling direct access to implementation mapping information.
//!
//! [`MethodImplRaw`]: crate::metadata::tables::MethodImplRaw
//! [`MethodImpl`]: crate::metadata::tables::MethodImpl

use crate::{
    metadata::{
        token::Token,
        typesystem::{CilTypeRc, CilTypeReference},
    },
    Result,
};

/// Owned `MethodImpl` table entry with resolved references and implementation mappings.
///
/// This structure represents a method implementation mapping with all coded indexes resolved
/// to their target structures and type references established. It provides complete
/// implementation mapping information for interface implementation, method overriding,
/// and virtual dispatch support in object-oriented programming.
///
/// # Implementation Mapping Types
/// `MethodImpl` entries support various implementation scenarios:
/// - **Interface implementation**: Maps interface method declarations to concrete class implementations
/// - **Virtual method override**: Specifies derived class methods that override base class methods
/// - **Explicit interface implementation**: Handles explicit implementation of interface members
/// - **Abstract method implementation**: Connects abstract declarations to concrete implementations
pub struct MethodImpl {
    /// Row identifier within the `MethodImpl` table.
    ///
    /// Unique identifier for this method implementation mapping entry, used for internal
    /// table management and cross-references.
    pub rid: u32,

    /// Metadata token identifying this `MethodImpl` entry.
    ///
    /// The token enables efficient lookup and reference to this implementation mapping
    /// from other metadata structures and runtime systems.
    pub token: Token,

    /// Byte offset of this entry within the raw table data.
    ///
    /// Used for efficient table navigation and binary metadata processing.
    pub offset: usize,

    /// Resolved reference to the class type containing the implementation mapping.
    ///
    /// Specifies the type that provides the concrete implementation for the method
    /// declaration. This class contains the method body that implements the interface
    /// contract or overrides the virtual method.
    pub class: CilTypeRc,

    /// Resolved reference to the concrete method implementation.
    ///
    /// Specifies the actual method that provides the implementation behavior.
    /// This method belongs to the class and contains the IL code or native
    /// implementation that fulfills the method contract.
    pub method_body: CilTypeReference,

    /// Resolved reference to the method declaration being implemented.
    ///
    /// Specifies the interface method, abstract method, or virtual method
    /// declaration that is being implemented by the method body. This establishes
    /// the contract that the implementation must fulfill.
    pub method_declaration: CilTypeReference,
}

impl MethodImpl {
    /// Applies this method implementation mapping to update type system relationships.
    ///
    /// This method establishes bidirectional relationships between method declarations
    /// and their implementations, updating both the implementing class and the declared
    /// method with cross-reference information. This enables efficient method resolution
    /// during virtual dispatch and interface member lookup operations.
    ///
    /// # Implementation Updates
    /// The method performs the following type system updates:
    /// - **Class overwrites**: Adds the method body to the class's overwrite collection
    /// - **Interface implementations**: Adds the implementation to the declaration's interface implementations
    /// - **Bidirectional linking**: Establishes cross-references for efficient lookup
    ///
    /// # Method Resolution Support
    /// These relationships enable sophisticated method resolution:
    /// - **Virtual dispatch**: Runtime can locate correct implementation for virtual calls
    /// - **Interface casting**: Interface method calls can be resolved to concrete implementations
    /// - **Reflection support**: Runtime reflection can discover implementation relationships
    /// - **Debugging information**: Development tools can trace method implementation chains
    ///
    /// # Returns
    /// * `Ok(())` - If the implementation mapping was applied successfully
    /// * `Err(_)` - If updating type system relationships fails (currently infallible)
    ///
    /// # Errors
    ///
    /// Returns an error if updating type system relationships fails (currently infallible).
    pub fn apply(&self) -> Result<()> {
        self.class
            .overwrites
            .push_row(self.token, self.method_body.clone());

        if let CilTypeReference::MethodDef(method_ref) = &self.method_declaration {
            if let Some(method) = method_ref.upgrade() {
                if let CilTypeReference::MethodDef(body_method_ref) = &self.method_body {
                    method
                        .interface_impls
                        .push_row(self.token, body_method_ref.clone());
                }
            }
        }

        // Store the declaration on the body method for .override emission
        if let CilTypeReference::MethodDef(body_ref) = &self.method_body {
            if let Some(body_method) = body_ref.upgrade() {
                body_method
                    .overrides
                    .push_row(self.token, self.method_declaration.clone());
            }
        }

        Ok(())
    }
}

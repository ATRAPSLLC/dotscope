//! Metadata table queries for the emulation context.
//!
//! Provides access to MemberRef, MethodSpec, standalone signatures, TypeSpec
//! signatures, and P/Invoke import resolution.

use std::sync::Arc;

use crate::{
    emulation::engine::context::EmulationContext,
    metadata::{
        imports::{Import, ImportSourceId, ImportType},
        signatures::SignatureTypeSpec,
        streams::SharedStr,
        tables::{
            MemberRef, MethodSpec, MethodSpecRc, StandAloneSigRaw, StandAloneSignature,
            TableAccess, TypeSpecRaw,
        },
        token::Token,
        typesystem::{CilTypeReference, FullName},
    },
};

impl EmulationContext {
    /// Gets a MemberRef by its token.
    ///
    /// MemberRef entries represent external method or field references
    /// (e.g., calls to BCL methods like `System.String.Concat`).
    ///
    /// # Returns
    ///
    /// The MemberRef if found, or `None` if the token doesn't exist.
    #[must_use]
    pub fn get_member_ref(&self, token: Token) -> Option<Arc<MemberRef>> {
        self.assembly
            .refs_members()
            .get(&token)
            .map(|e| e.value().clone())
    }

    /// Gets a method specification by its token.
    ///
    /// MethodSpec entries represent generic method instantiations with concrete
    /// type arguments (e.g., calls to `List<T>.Add` with `T = int`).
    ///
    /// # Arguments
    ///
    /// * `token` - A MethodSpec metadata token (table 0x2B)
    ///
    /// # Returns
    ///
    /// The MethodSpec if found, or `None` if the token doesn't exist.
    #[must_use]
    pub fn get_method_spec(&self, token: Token) -> Option<MethodSpecRc> {
        self.assembly
            .method_specs()
            .get(&token)
            .map(|e| e.value().clone())
    }

    /// Resolves a MethodSpec token to its underlying method token.
    ///
    /// For generic method instantiations, this extracts the token of the actual
    /// method being called (either a MethodDef or MemberRef).
    ///
    /// # Arguments
    ///
    /// * `method_spec` - The MethodSpec to resolve
    ///
    /// # Returns
    ///
    /// The token of the underlying method, or `None` if resolution fails.
    #[must_use]
    pub fn resolve_method_spec_to_token(method_spec: &MethodSpec) -> Option<Token> {
        match &method_spec.method {
            CilTypeReference::MethodDef(method_ref) => method_ref.upgrade().map(|m| m.token),
            CilTypeReference::MemberRef(member_ref) => Some(member_ref.token),
            _ => None,
        }
    }

    /// Gets a standalone signature by its token.
    ///
    /// Standalone signatures are used for:
    /// - `calli` instructions (method call site signatures)
    /// - Local variable declarations
    /// - Function pointer types
    ///
    /// # Arguments
    ///
    /// * `token` - A StandAloneSig metadata token (table 0x11)
    ///
    /// # Returns
    ///
    /// The parsed signature if found, or `None` if the token doesn't exist.
    #[must_use]
    pub fn get_standalone_signature(&self, token: Token) -> Option<StandAloneSignature> {
        let tables = self.assembly.tables()?;
        let blob = self.assembly.blob()?;
        let table = <_ as TableAccess<StandAloneSigRaw>>::table(tables)?;
        let row = token.row();
        let raw_sig = table.get(row).ok().flatten()?;
        // Parse the raw signature using the blob heap
        let owned_sig = raw_sig.to_owned(blob).ok()?;
        Some(owned_sig.parsed_signature.clone())
    }

    /// Gets the signature of a TypeSpec by its token.
    ///
    /// TypeSpec entries represent complex types through signatures in the blob heap,
    /// including generic instantiations, array types, and type parameters.
    ///
    /// # Arguments
    ///
    /// * `token` - A TypeSpec metadata token (table 0x1B)
    ///
    /// # Returns
    ///
    /// The parsed TypeSpec signature if found, or `None` if the token doesn't exist.
    #[must_use]
    pub fn get_typespec_signature(&self, token: Token) -> Option<SignatureTypeSpec> {
        // Only handle TypeSpec tokens (table 0x1B)
        if token.table() != 0x1B {
            return None;
        }

        let tables = self.assembly.tables()?;
        let blob = self.assembly.blob()?;
        let table = <_ as TableAccess<TypeSpecRaw>>::table(tables)?;
        let row = token.row();
        let raw_typespec = table.get(row).ok().flatten()?;
        // Parse the raw signature using the blob heap
        let owned_typespec = raw_typespec.to_owned(blob).ok()?;
        Some(owned_typespec.signature.clone())
    }

    /// Finds a P/Invoke import by the method it's associated with.
    ///
    /// P/Invoke imports are used for calling native code from managed code.
    /// This searches the assembly's imports to find one matching the given
    /// method token.
    ///
    /// # Arguments
    ///
    /// * `method_token` - Token of the method to find imports for
    ///
    /// # Returns
    ///
    /// The import information if found, or `None` if no import exists
    /// for this method.
    #[must_use]
    pub fn find_import_by_method(&self, method_token: Token) -> Option<Arc<Import>> {
        for import_entry in self.assembly.imports().cil() {
            let import = import_entry.value();
            if let ImportType::Method(import_method) = &import.import {
                if import_method.token == method_token {
                    return Some(import.clone());
                }
            }
        }
        None
    }

    /// Gets the DLL/module name from a P/Invoke import.
    ///
    /// For imports from external modules (P/Invoke), this returns the DLL name
    /// (e.g., "kernel32.dll"). For other import types, returns `None`.
    ///
    /// # Arguments
    ///
    /// * `import` - The import to get the DLL name from
    ///
    /// # Returns
    ///
    /// The DLL name if this is a ModuleRef-sourced import, or `None` otherwise.
    #[must_use]
    pub fn get_import_dll_name(&self, import: &Import) -> Option<SharedStr> {
        match import.source_id {
            ImportSourceId::ModuleRef(token) => self
                .assembly
                .imports()
                .cil()
                .get_module_ref(token)
                .map(|module_ref| module_ref.name.clone()),
            _ => None,
        }
    }

    /// Extracts type name and namespace from a MemberRef's parent type reference.
    ///
    /// This is useful for identifying the declaring type of external method
    /// references without having to manually handle weak reference upgrades.
    ///
    /// # Arguments
    ///
    /// * `member_ref` - The MemberRef to extract type info from
    ///
    /// # Returns
    ///
    /// A tuple of (namespace, name), or `None` if the type reference is invalid.
    #[must_use]
    pub fn get_member_ref_type_info(member_ref: &MemberRef) -> Option<(SharedStr, SharedStr)> {
        match &member_ref.declaredby {
            CilTypeReference::TypeRef(cil_type_ref)
            | CilTypeReference::TypeDef(cil_type_ref)
            | CilTypeReference::TypeSpec(cil_type_ref) => cil_type_ref.upgrade().map(|t| {
                // Resolve namespace from enclosing type for nested types.
                // Nested types have empty namespace in metadata but inherit their
                // enclosing type's namespace (e.g., List`1/Enumerator → "System.Collections.Generic").
                let namespace = if t.namespace.is_empty() {
                    t.enclosing_type()
                        .map(|enc| enc.namespace.clone())
                        .filter(|ns| !ns.is_empty())
                        .unwrap_or_default()
                } else {
                    t.namespace.clone()
                };
                (namespace, t.name.clone())
            }),
            _ => None,
        }
    }

    /// Gets the full type name from a MemberRef's parent type reference.
    ///
    /// Returns the fully qualified type name (e.g., "System.String") or
    /// extracts what's available from the reference.
    ///
    /// # Arguments
    ///
    /// * `member_ref` - The MemberRef to extract type name from
    ///
    /// # Returns
    ///
    /// The type name string, or "Unknown" if the reference is invalid.
    #[must_use]
    pub fn get_member_ref_type_name(member_ref: &MemberRef) -> FullName {
        match &member_ref.declaredby {
            CilTypeReference::ModuleRef(m) => {
                FullName::top_level(SharedStr::default(), m.name.clone())
            }
            _ => member_ref.declaredby.fullname().unwrap_or_else(|| {
                FullName::top_level(SharedStr::default(), SharedStr::from("Unknown"))
            }),
        }
    }

    /// Gets the token from a MemberRef's parent type reference.
    ///
    /// # Arguments
    ///
    /// * `member_ref` - The MemberRef to extract token from
    ///
    /// # Returns
    ///
    /// The type token if the reference is valid, or `None` otherwise.
    #[must_use]
    pub fn get_member_ref_type_token(member_ref: &MemberRef) -> Option<Token> {
        match &member_ref.declaredby {
            CilTypeReference::TypeRef(cil_type_ref)
            | CilTypeReference::TypeDef(cil_type_ref)
            | CilTypeReference::TypeSpec(cil_type_ref) => cil_type_ref.upgrade().map(|t| t.token),
            CilTypeReference::ModuleRef(m) => Some(m.token),
            _ => None,
        }
    }
}

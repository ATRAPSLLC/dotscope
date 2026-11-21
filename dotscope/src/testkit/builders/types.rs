//! Type builders for creating mock CilType and related type instances
//!
//! This module provides builders for creating CilType and ExportedType instances
//! with various characteristics including inheritance, interfaces, and value types.

use std::sync::{Arc, OnceLock};

use crate::{
    metadata::{
        tables::{ExportedType, ExportedTypeRc, TypeAttributes},
        token::Token,
        typesystem::{CilFlavor, CilType, CilTypeRc, CilTypeReference},
    },
    testkit::FileBuilder,
    utils::LazyList,
};

/// Builder for creating mock CilType instances with various characteristics
pub struct CilTypeBuilder {
    token: Token,
    namespace: String,
    name: String,
    external: Option<CilTypeReference>,
    flavor: Option<CilFlavor>,
    flags: TypeAttributes,
}

impl CilTypeBuilder {
    pub fn new() -> Self {
        Self {
            token: Token::new(0x02000001),
            namespace: "Test".to_string(),
            name: "TestType".to_string(),
            external: None,
            flavor: Some(CilFlavor::Class),
            flags: TypeAttributes::ZERO,
        }
    }

    pub fn with_token(mut self, token: Token) -> Self {
        self.token = token;
        self
    }

    pub fn with_namespace(mut self, namespace: &str) -> Self {
        self.namespace = namespace.to_string();
        self
    }

    pub fn with_name(mut self, name: &str) -> Self {
        self.name = name.to_string();
        self
    }

    pub fn with_external(mut self, external: CilTypeReference) -> Self {
        self.external = Some(external);
        self
    }

    pub fn with_flavor(mut self, flavor: CilFlavor) -> Self {
        self.flavor = Some(flavor);
        self
    }

    pub fn with_flags(mut self, flags: TypeAttributes) -> Self {
        self.flags = flags;
        self
    }

    /// Leaves the flavor to the type's own computation from its flags and base.
    pub fn with_computed_flavor(mut self) -> Self {
        self.flavor = None;
        self
    }

    /// Create a simple class type
    pub fn simple_class(namespace: &str, name: &str) -> Self {
        Self::new()
            .with_namespace(namespace)
            .with_name(name)
            .with_flavor(CilFlavor::Class)
    }

    /// Create an interface type
    pub fn interface(namespace: &str, name: &str) -> Self {
        Self::new()
            .with_namespace(namespace)
            .with_name(name)
            .with_flavor(CilFlavor::Interface)
    }

    pub fn build(self) -> CilTypeRc {
        Arc::new(CilType::new(
            self.token,
            self.namespace,
            self.name,
            self.external,
            None, // base type
            self.flags,
            LazyList::new(), // fields
            LazyList::new(), // methods
            self.flavor,
        ))
    }
}

impl Default for CilTypeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper function to create an ExportedTypeRc
pub fn create_exportedtype(dummy_type: CilTypeRc) -> ExportedTypeRc {
    let implementation_lock = OnceLock::new();
    implementation_lock
        .set(CilTypeReference::File(
            FileBuilder::new()
                .with_rid(1)
                .with_name("export_test")
                .build(),
        ))
        .ok();

    Arc::new(ExportedType {
        rid: 1,
        token: Token::new(0x27000001),
        offset: 0,
        flags: TypeAttributes::ZERO,
        type_def_id: dummy_type.token.0,
        name: "ExportedType".into(),
        namespace: Some("Test.Namespace".into()),
        implementation: implementation_lock,
        custom_attributes: Default::default(),
    })
}

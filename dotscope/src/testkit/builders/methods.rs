//! Method builders for creating mock method instances with complex configurations
//!
//! This module provides builders for creating Method instances with various
//! signatures, flags, and metadata configurations for comprehensive testing.

use std::sync::{atomic::AtomicU32, Arc, OnceLock};

use crate::{
    metadata::{
        method::{
            Method, MethodAccessFlags, MethodImplCodeType, MethodImplManagement, MethodImplOptions,
            MethodModifiers, MethodRc, MethodVtableFlags,
        },
        signatures::{SignatureMethod, SignatureParameter, TypeSignature},
        tables::ParamList,
        token::Token,
        typesystem::{CilFlavor, TypeRegistry},
    },
    testkit::builders::params::ParamBuilder,
    utils::{LazyList, RowList},
};

/// Builder for creating mock Method instances with complex configurations
pub struct MethodBuilder {
    rid: u32,
    name: String,
    flags_access: MethodAccessFlags,
    flags_vtable: MethodVtableFlags,
    flags_modifiers: MethodModifiers,
    impl_code_type: MethodImplCodeType,
    impl_management: MethodImplManagement,
    impl_options: MethodImplOptions,
    signature: Option<SignatureMethod>,
    rva: Option<u32>,
    param_builders: Vec<ParamBuilder>,
    auto_create_params: bool,
}

impl MethodBuilder {
    pub fn new() -> Self {
        Self {
            rid: 1,
            name: "TestMethod".to_string(),
            flags_access: MethodAccessFlags::PUBLIC,
            flags_vtable: MethodVtableFlags::ZERO,
            flags_modifiers: MethodModifiers::ZERO,
            impl_code_type: MethodImplCodeType::IL,
            impl_management: MethodImplManagement::ZERO,
            impl_options: MethodImplOptions::ZERO,
            signature: None,
            rva: Some(0x1000),
            param_builders: Vec::new(),
            auto_create_params: true,
        }
    }

    pub fn with_rid(mut self, rid: u32) -> Self {
        self.rid = rid;
        self
    }

    pub fn with_name(mut self, name: &str) -> Self {
        self.name = name.to_string();
        self
    }

    pub fn with_rva(mut self, rva: u32) -> Self {
        self.rva = Some(rva);
        self
    }

    pub fn without_rva(mut self) -> Self {
        self.rva = None;
        self
    }

    /// Create a simple void method with no parameters
    pub fn simple_void_method(name: &str) -> Self {
        Self::new().with_name(name).with_signature(SignatureMethod {
            has_this: false,
            explicit_this: false,
            default: false,
            vararg: false,
            cdecl: true,
            stdcall: false,
            thiscall: false,
            fastcall: false,
            unmanaged: false,
            param_count_generic: 0,
            param_count: 0,
            return_type: SignatureParameter {
                modifiers: Vec::new(),
                by_ref: false,
                base: TypeSignature::Void,
            },
            params: Vec::new(),
            varargs: Vec::new(),
        })
    }

    pub fn with_signature(mut self, signature: SignatureMethod) -> Self {
        self.signature = Some(signature);
        self
    }

    /// Disable automatic parameter creation from signature
    pub fn without_auto_params(mut self) -> Self {
        self.auto_create_params = false;
        self
    }

    pub fn with_modifiers(mut self, modifiers: MethodModifiers) -> Self {
        self.flags_modifiers = modifiers;
        self
    }

    pub fn with_impl_code_type(mut self, impl_code_type: MethodImplCodeType) -> Self {
        self.impl_code_type = impl_code_type;
        self
    }

    /// Add a typed input parameter by name and type flavor
    pub fn add_typed_param(mut self, name: &str, type_flavor: CilFlavor) -> Self {
        let sequence = self.param_builders.len() as u32 + 1;
        self.param_builders
            .push(ParamBuilder::input_param(sequence, name).with_type_from_flavor(type_flavor));
        self
    }

    /// Create a method with specific parameter types (convenience for custom attribute testing)
    pub fn with_param_types(name: &str, param_types: Vec<CilFlavor>) -> Self {
        let mut builder = Self::new().with_name(name).without_auto_params();

        for (index, param_type) in param_types.into_iter().enumerate() {
            builder = builder.add_typed_param(&format!("param{}", index + 1), param_type);
        }

        builder
    }

    pub fn build(self) -> MethodRc {
        self.build_with_registry(None)
    }

    pub fn build_with_registry(self, type_registry: Option<&Arc<TypeRegistry>>) -> MethodRc {
        // Build parameters - either from explicit builders or auto-generated from signature
        let params = if !self.param_builders.is_empty() {
            // Use explicitly provided parameter builders
            let param_vec = ParamList::new();
            for param_builder in self.param_builders {
                param_vec.push(param_builder.build(type_registry));
            }
            param_vec
        } else if self.auto_create_params {
            // Auto-generate parameters from signature
            let param_vec = ParamList::new();
            if let Some(ref signature) = self.signature {
                for (index, _param_sig) in signature.params.iter().enumerate() {
                    let param = ParamBuilder::input_param(
                        (index + 1) as u32,
                        &format!("param{}", index + 1),
                    )
                    .build(type_registry);
                    param_vec.push(param);
                }
            }
            param_vec
        } else {
            // No parameters
            ParamList::new()
        };

        Arc::new(Method {
            rid: self.rid,
            token: Token::new(0x06000000 + self.rid),
            meta_offset: 0,
            impl_code_type: self.impl_code_type,
            impl_management: self.impl_management,
            impl_options: self.impl_options,
            flags_access: self.flags_access,
            flags_vtable: self.flags_vtable,
            flags_modifiers: self.flags_modifiers,
            flags_pinvoke: AtomicU32::new(0),
            name: self.name,
            params,
            generic_params: Default::default(),
            generic_args: LazyList::new(),
            signature: self.signature.unwrap_or_else(|| SignatureMethod {
                has_this: false,
                explicit_this: false,
                default: false,
                vararg: false,
                cdecl: true,
                stdcall: false,
                thiscall: false,
                fastcall: false,
                unmanaged: false,
                param_count_generic: 0,
                param_count: 0,
                return_type: SignatureParameter {
                    modifiers: Vec::new(),
                    by_ref: false,
                    base: TypeSignature::Void,
                },
                params: Vec::new(),
                varargs: Vec::new(),
            }),
            rva: self.rva,
            body: OnceLock::new(),
            local_vars: LazyList::new(),
            overrides: Default::default(),
            interface_impls: Default::default(),
            security: RowList::new(),
            blocks: OnceLock::new(),
            custom_attributes: Default::default(),
            declaring_type: OnceLock::new(),
        })
    }
}

impl Default for MethodBuilder {
    fn default() -> Self {
        Self::new()
    }
}

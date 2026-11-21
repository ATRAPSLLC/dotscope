//! Method introspection and instruction access for the emulation context.
//!
//! Provides method metadata lookup, instruction retrieval, parameter/return type
//! inspection, and local variable type resolution.

use std::sync::Arc;

use crate::{
    assembly::Instruction,
    emulation::{
        engine::{
            context::{EmulationContext, MethodCode},
            error::EmulationError,
        },
        exception::ExceptionClause,
    },
    metadata::{
        method::Method,
        signatures::{SignatureMethod, TypeSignature},
        tables::{MemberRefSignature, TableId},
        token::Token,
        typesystem::{CilFlavor, CilTypeReference},
    },
    prelude::ExceptionHandlerFlags,
    Result,
};

impl EmulationContext {
    /// Gets a method by its token.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::MethodNotFound`] if the method token is not found.
    pub fn get_method(&self, token: Token) -> Result<Arc<Method>> {
        self.assembly
            .methods()
            .get(&token)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| EmulationError::MethodNotFound { token }.into())
    }

    /// Gets the instructions for a method.
    ///
    /// Checks synthetic methods first (from `DynamicMethod`/`ILGenerator`),
    /// then falls through to assembly metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the method is not found or has no body.
    pub fn get_instructions(&self, method_token: Token) -> Result<Vec<Instruction>> {
        // Check synthetic methods first
        if let Some(synthetic) = self.synthetic_methods.get(&method_token) {
            return Ok(synthetic.instructions.clone());
        }

        // Serve from the code cache when possible so repeated callers do not
        // re-decode the whole body.
        if let Some(code) = self.code_cache.get(&method_token) {
            return Ok(code.instructions().to_vec());
        }

        let method = self.get_method(method_token)?;

        // Get instructions from the method's blocks
        let instructions: Vec<Instruction> = method.instructions().cloned().collect();
        if instructions.is_empty() && !method.has_body() {
            return Err(EmulationError::MissingMethodBody {
                token: method_token,
            }
            .into());
        }
        Ok(instructions)
    }

    /// Gets the offset-indexed, cached body for a method.
    ///
    /// The body is decoded once per method token and shared behind an `Arc`.
    /// Both instruction fetch and RVA-to-offset conversion are O(1) against the
    /// returned value, which is what the execution loop relies on.
    ///
    /// Synthetic method bodies are not cached — `ILGenerator` can mutate them
    /// after registration — so they are rebuilt on each call.
    ///
    /// # Errors
    ///
    /// Returns an error if the method is not found or has no decodable body.
    pub fn get_method_code(&self, method_token: Token) -> Result<Arc<MethodCode>> {
        if let Some(code) = self.code_cache.get(&method_token) {
            return Ok(Arc::clone(code.value()));
        }

        // Synthetic bodies are mutable at runtime; build fresh and do not cache.
        if let Some(synthetic) = self.synthetic_methods.get(&method_token) {
            return MethodCode::new(synthetic.instructions.clone())
                .map(Arc::new)
                .ok_or_else(|| {
                    EmulationError::MissingMethodBody {
                        token: method_token,
                    }
                    .into()
                });
        }

        let method = self.get_method(method_token)?;
        let instructions: Vec<Instruction> = method.instructions().cloned().collect();

        // An empty list means either a genuinely bodiless method or a body whose
        // blocks have not been decoded yet. Neither is safe to cache.
        let Some(code) = MethodCode::new(instructions) else {
            return Err(EmulationError::MissingMethodBody {
                token: method_token,
            }
            .into());
        };

        let code = Arc::new(code);
        self.code_cache.insert(method_token, Arc::clone(&code));
        Ok(code)
    }

    /// Gets the base RVA (address of the first instruction) of a method.
    ///
    /// This is used to convert between absolute RVAs and method-relative offsets.
    ///
    /// # Errors
    ///
    /// Returns an error if the method is not found or has no instructions.
    pub fn get_method_base_rva(&self, method_token: Token) -> Result<u64> {
        Ok(self.get_method_code(method_token)?.base_rva())
    }

    /// Converts an absolute RVA to a method-relative offset.
    ///
    /// Branch targets in CIL are stored as absolute RVAs, but the instruction
    /// pointer uses method-relative offsets. This function converts between them.
    ///
    /// # Errors
    ///
    /// Returns an error if the method is not found.
    /// Method-relative offsets are bounded by IL method body size (< u32::MAX)
    pub fn rva_to_method_offset(&self, method_token: Token, rva: u64) -> Result<u32> {
        Ok(self.get_method_code(method_token)?.rva_to_offset(rva))
    }

    /// Gets an instruction at a specific method-relative offset.
    ///
    /// The offset is relative to the start of the method's IL code (0 = first instruction).
    /// This is the offset used by CIL branch instructions and the instruction pointer.
    ///
    /// # Errors
    ///
    /// Returns an error if the method is not found or no instruction exists at the offset.
    pub fn get_instruction_at(&self, method_token: Token, offset: u32) -> Result<Instruction> {
        self.get_method_code(method_token)?
            .instruction_at(offset)
            .cloned()
            .ok_or_else(|| EmulationError::InvalidInstructionPointer { offset }.into())
    }

    /// Gets an instruction by index within a method's instruction list.
    ///
    /// # Errors
    ///
    /// Returns an error if the method is not found or the index is out of bounds.
    pub fn get_instruction_by_index(
        &self,
        method_token: Token,
        index: usize,
    ) -> Result<Instruction> {
        let instructions = self.get_instructions(method_token)?;

        instructions.into_iter().nth(index).ok_or_else(|| {
            EmulationError::InvalidInstructionPointer {
                offset: u32::try_from(index).unwrap_or(u32::MAX),
            }
            .into()
        })
    }

    /// Gets a user string from the #US heap.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::UserStringNotFound`] if the string is not found.
    pub fn get_user_string(&self, index: u32) -> Result<String> {
        let userstrings = self
            .assembly
            .userstrings()
            .ok_or(EmulationError::UserStringNotFound { index })?;

        let idx =
            usize::try_from(index).map_err(|_| EmulationError::UserStringNotFound { index })?;

        let string_data = userstrings
            .get(idx)
            .map_err(|_| EmulationError::UserStringNotFound { index })?;

        Ok(string_data.to_string_lossy())
    }

    /// Gets the local variable types for a method.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::MethodNotFound`] if the method is not found.
    /// Returns [`EmulationError::TypeNotFound`] if a local variable's type reference is dead.
    pub fn get_local_types(&self, method_token: Token) -> Result<Vec<CilFlavor>> {
        // Check synthetic methods first
        if let Some(synthetic) = self.synthetic_methods.get(&method_token) {
            return Ok(synthetic.local_types.clone());
        }

        let method = self.get_method(method_token)?;

        // Get locals from the method's local_vars field
        // boxcar::Vec iter returns (index, &value) tuples
        let mut locals = Vec::new();
        for (index, local) in method.local_vars.iter() {
            let Ok(idx) = u16::try_from(index) else {
                continue; // Skip locals with index > u16::MAX
            };

            // Resolve the type from the CilTypeRef
            let cil_flavor = match local.base.upgrade() {
                Some(cil_type) => cil_type.flavor().clone(),
                None => {
                    // Type reference is dead - this is an error condition
                    return Err(EmulationError::TypeNotFound {
                        method_token,
                        local_index: idx,
                    }
                    .into());
                }
            };

            locals.push(cil_flavor);
        }

        Ok(locals)
    }

    /// Checks if a method returns a value (non-void).
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::MethodNotFound`] if the method is not found.
    pub fn method_returns_value(&self, method_token: Token) -> Result<bool> {
        if let Some(body) = self.synthetic_methods.get(&method_token) {
            return Ok(body.returns_value);
        }

        let method = self.get_method(method_token)?;

        // Check the return type from the method signature (it's in .base field)
        Ok(!matches!(
            method.signature.return_type.base,
            TypeSignature::Void
        ))
    }

    /// Gets the return type of a call to `method_token` as a CilFlavor: a MethodDef's, a
    /// MemberRef's or a MethodSpec's (see [`Self::with_call_signature`]).
    ///
    /// Returns `None` if the method returns void.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::MethodNotFound`] if the token names no method.
    pub fn get_return_type(&self, method_token: Token) -> Result<Option<CilFlavor>> {
        self.with_call_signature(method_token, |signature| {
            (!matches!(signature.return_type.base, TypeSignature::Void))
                .then(|| CilFlavor::from(&signature.return_type.base))
        })
    }

    /// Gets the parameter types of a call to `method_token` as CilFlavors: a MethodDef's, a
    /// MemberRef's or a MethodSpec's (see [`Self::with_call_signature`]), or a synthetic
    /// method's.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::MethodNotFound`] if the token names no method.
    pub fn get_parameter_types(&self, method_token: Token) -> Result<Vec<CilFlavor>> {
        // Check synthetic methods first
        if let Some(synthetic) = self.synthetic_methods.get(&method_token) {
            return Ok(synthetic.param_types.clone());
        }

        self.with_call_signature(method_token, |signature| {
            signature
                .params
                .iter()
                .map(|param| CilFlavor::from(&param.base))
                .collect()
        })
    }

    /// Runs `read` on the signature a call to `method_token` is made with: a MethodDef's
    /// own, a MemberRef's (a method of another assembly, which is every framework method a
    /// hook stands for), or, for a MethodSpec, that of the generic method it instantiates.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::MethodNotFound`] when the token names no method, or a
    /// MemberRef that is a field.
    pub fn with_call_signature<R>(
        &self,
        method_token: Token,
        read: impl FnOnce(&SignatureMethod) -> R,
    ) -> Result<R> {
        let not_found = || -> crate::Error {
            EmulationError::MethodNotFound {
                token: method_token,
            }
            .into()
        };
        match TableId::from_token_type(method_token.table()) {
            Some(TableId::MemberRef) => {
                let member = self
                    .assembly
                    .member_ref(&method_token)
                    .ok_or_else(not_found)?;
                match &member.signature {
                    MemberRefSignature::Method(signature) => Ok(read(signature)),
                    MemberRefSignature::Field(_) => Err(not_found()),
                }
            }
            Some(TableId::MethodSpec) => {
                let spec = self.assembly.method_spec(&method_token)?;
                let generic = match &spec.method {
                    CilTypeReference::MethodDef(method) => method.token(),
                    CilTypeReference::MemberRef(member) => Some(member.token),
                    _ => None,
                }
                .ok_or_else(not_found)?;
                self.with_call_signature(generic, read)
            }
            _ => Ok(read(&self.get_method(method_token)?.signature)),
        }
    }

    /// Gets the maximum stack size for a method.
    ///
    /// # Errors
    ///
    /// Returns an error if the method is not found, has no body, or has invalid metadata.
    pub fn get_max_stack(&self, method_token: Token) -> Result<u16> {
        // Synthetic methods: use a generous default
        if self.synthetic_methods.contains_key(&method_token) {
            return Ok(16);
        }

        let method = self.get_method(method_token)?;

        let body = method.body.get().ok_or(EmulationError::MissingMethodBody {
            token: method_token,
        })?;

        u16::try_from(body.max_stack).map_err(|_| {
            EmulationError::InvalidMethodMetadata {
                token: method_token,
                reason: "max_stack exceeds u16::MAX",
            }
            .into()
        })
    }

    /// Gets the parameter count for a method.
    ///
    /// Uses the method signature blob (authoritative source) rather than the Param
    /// table, which may have fewer entries than the actual parameter count.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::MethodNotFound`] if the method is not found.
    pub fn get_parameter_count(&self, method_token: Token) -> Result<usize> {
        let method = self.get_method(method_token)?;
        Ok(method.signature.params.len())
    }

    /// Checks if a method is static.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::MethodNotFound`] if the method is not found.
    pub fn is_static_method(&self, method_token: Token) -> Result<bool> {
        // Check synthetic methods first
        if let Some(synthetic) = self.synthetic_methods.get(&method_token) {
            return Ok(synthetic.is_static);
        }

        let method = self.get_method(method_token)?;
        Ok(method.is_static())
    }

    /// Converts exception handlers from metadata format to emulation format.
    pub fn convert_exception_handlers(&self, method_token: Token) -> Result<Vec<ExceptionClause>> {
        let method = self.get_method(method_token)?;
        let body = method.body.get().ok_or(EmulationError::MissingMethodBody {
            token: method_token,
        })?;

        let mut clauses = Vec::new();
        for handler in &body.exception_handlers {
            let clause = if handler.flags == ExceptionHandlerFlags::EXCEPTION {
                // Catch clause - get the type token from the handler field
                let catch_type = handler
                    .handler
                    .as_ref()
                    .map_or_else(|| Token::new(handler.filter_offset), |t| t.token);

                ExceptionClause::Catch {
                    try_offset: handler.try_offset,
                    try_length: handler.try_length,
                    handler_offset: handler.handler_offset,
                    handler_length: handler.handler_length,
                    catch_type,
                }
            } else if handler.flags == ExceptionHandlerFlags::FILTER {
                ExceptionClause::Filter {
                    try_offset: handler.try_offset,
                    try_length: handler.try_length,
                    handler_offset: handler.handler_offset,
                    handler_length: handler.handler_length,
                    filter_offset: handler.filter_offset,
                }
            } else if handler.flags == ExceptionHandlerFlags::FINALLY {
                ExceptionClause::Finally {
                    try_offset: handler.try_offset,
                    try_length: handler.try_length,
                    handler_offset: handler.handler_offset,
                    handler_length: handler.handler_length,
                }
            } else if handler.flags == ExceptionHandlerFlags::FAULT {
                ExceptionClause::Fault {
                    try_offset: handler.try_offset,
                    try_length: handler.try_length,
                    handler_offset: handler.handler_offset,
                    handler_length: handler.handler_length,
                }
            } else {
                // Unknown handler type - skip it
                continue;
            };
            clauses.push(clause);
        }

        Ok(clauses)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use dashmap::DashMap;

    use super::*;
    use crate::{testkit::fixture, CilObject};

    /// A call to a method of another assembly is a MemberRef, which is how every framework
    /// method a hook stands for is called: its parameter and return types come from the
    /// MemberRef's own signature, and a MemberRef naming a field is no method.
    #[test]
    fn a_member_ref_answers_with_its_signature() {
        let assembly = Arc::new(CilObject::from_path(fixture("crafted_2.exe")).unwrap());
        let context = EmulationContext::new(Arc::clone(&assembly), Arc::new(DashMap::new()));
        let (mut methods, mut fields) = (0, 0);
        for entry in assembly.refs_members().iter() {
            let member = entry.value();
            match &member.signature {
                MemberRefSignature::Method(signature) => {
                    let params: Vec<CilFlavor> = signature
                        .params
                        .iter()
                        .map(|param| CilFlavor::from(&param.base))
                        .collect();
                    assert_eq!(
                        context.get_parameter_types(member.token).unwrap(),
                        params,
                        "{}",
                        member.name
                    );
                    let returns = (!matches!(signature.return_type.base, TypeSignature::Void))
                        .then(|| CilFlavor::from(&signature.return_type.base));
                    assert_eq!(context.get_return_type(member.token).unwrap(), returns);
                    methods += 1;
                }
                MemberRefSignature::Field(_) => {
                    assert!(context.get_parameter_types(member.token).is_err());
                    fields += 1;
                }
            }
        }
        assert!(methods > 0, "the sample calls methods of other assemblies");
        let _ = fields;
    }
}

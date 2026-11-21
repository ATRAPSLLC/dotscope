//! Generic parameter substitution and type signature resolution for the emulation context.
//!
//! Provides conversion of `TypeSignature` to metadata tokens and substitution of
//! generic type/method parameters in method signatures.

use crate::{
    emulation::{
        engine::{context::EmulationContext, generics::GenericRegistry},
        tokens,
    },
    metadata::{
        signatures::{
            SignatureArray, SignatureMethod, SignatureParameter, SignaturePointer,
            SignatureSzArray, TypeSignature,
        },
        token::Token,
        typesystem::CilPrimitiveKind,
    },
};

impl EmulationContext {
    /// Converts a `TypeSignature` to a metadata `Token`.
    ///
    /// Maps primitive type signatures to their well-known `CilPrimitiveKind` tokens
    /// (`0xF000_xxxx`), concrete class/value type references to their tokens,
    /// and generic instantiations to synthetic tokens via `GenericRegistry`.
    ///
    /// Generic parameters (`GenericParamType`/`GenericParamMethod`) are resolved
    /// from the provided type/method argument lists when available.
    ///
    /// # Arguments
    ///
    /// * `sig` - The type signature to resolve
    /// * `type_args` - Type-level generic arguments (`!0`, `!1`, ...) if available
    /// * `method_args` - Method-level generic arguments (`!!0`, `!!1`, ...) if available
    /// * `generics` - Generic registry for creating synthetic instantiation tokens
    #[must_use]
    pub fn type_signature_to_token(
        &self,
        sig: &TypeSignature,
        type_args: Option<&[Token]>,
        method_args: Option<&[Token]>,
        generics: &GenericRegistry,
    ) -> Option<Token> {
        match sig {
            // Primitive types → well-known tokens
            TypeSignature::Void => Some(CilPrimitiveKind::Void.token()),
            TypeSignature::Boolean => Some(CilPrimitiveKind::Boolean.token()),
            TypeSignature::Char => Some(CilPrimitiveKind::Char.token()),
            TypeSignature::I1 => Some(CilPrimitiveKind::I1.token()),
            TypeSignature::U1 => Some(CilPrimitiveKind::U1.token()),
            TypeSignature::I2 => Some(CilPrimitiveKind::I2.token()),
            TypeSignature::U2 => Some(CilPrimitiveKind::U2.token()),
            TypeSignature::I4 => Some(CilPrimitiveKind::I4.token()),
            TypeSignature::U4 => Some(CilPrimitiveKind::U4.token()),
            TypeSignature::I8 => Some(CilPrimitiveKind::I8.token()),
            TypeSignature::U8 => Some(CilPrimitiveKind::U8.token()),
            TypeSignature::R4 => Some(CilPrimitiveKind::R4.token()),
            TypeSignature::R8 => Some(CilPrimitiveKind::R8.token()),
            TypeSignature::I => Some(CilPrimitiveKind::I.token()),
            TypeSignature::U => Some(CilPrimitiveKind::U.token()),
            TypeSignature::String => Some(CilPrimitiveKind::String.token()),
            TypeSignature::Object => Some(CilPrimitiveKind::Object.token()),
            TypeSignature::TypedByRef => Some(CilPrimitiveKind::TypedReference.token()),

            // Concrete class or value type → direct token
            TypeSignature::Class(token) | TypeSignature::ValueType(token) => Some(*token),

            // Generic type parameter (!0, !1, ...) → resolve from type args
            TypeSignature::GenericParamType(index) => {
                type_args.and_then(|args| args.get(*index as usize).copied())
            }

            // Generic method parameter (!!0, !!1, ...) → resolve from method args
            TypeSignature::GenericParamMethod(index) => {
                method_args.and_then(|args| args.get(*index as usize).copied())
            }

            // Generic instantiation (e.g., List<int>) → register in GenericRegistry
            TypeSignature::GenericInst(base, args) => {
                let base_token =
                    self.type_signature_to_token(base, type_args, method_args, generics)?;
                let arg_tokens: Vec<Token> = args
                    .iter()
                    .filter_map(|a| {
                        self.type_signature_to_token(a, type_args, method_args, generics)
                    })
                    .collect();
                if arg_tokens.len() != args.len() {
                    return None; // Could not resolve all args
                }
                Some(generics.get_or_create_type(base_token, arg_tokens))
            }

            // SzArray (T[]) → encode as an SzArray primitive token that preserves
            // the array-ness. For primitive element types (byte, int, etc.), the token
            // is SZARRAY_PRIMITIVE_BASE | element_kind_id. This allows GetTypeFromHandle
            // and GetElementType to correctly handle typeof(byte[]).GetElementType()→byte.
            TypeSignature::SzArray(sz_array) => {
                let elem_token =
                    self.type_signature_to_token(&sz_array.base, type_args, method_args, generics)?;
                // For primitive element types (0xF000_00xx), encode as SzArray primitive
                let elem_value = elem_token.value();
                if elem_value & 0xFFFF_FF00 == 0xF000_0000 {
                    let kind_id = elem_value & 0xFF;
                    Some(Token::new(tokens::ranges::SZARRAY_PRIMITIVE_BASE | kind_id))
                } else {
                    // Non-primitive array types (e.g., object[]) — register in
                    // GenericRegistry with a well-known sentinel base
                    let sentinel = Token::new(tokens::ranges::SZARRAY_PRIMITIVE_BASE);
                    Some(generics.get_or_create_type(sentinel, vec![elem_token]))
                }
            }

            // ByRef — unwrap and return inner token
            TypeSignature::ByRef(inner) => {
                self.type_signature_to_token(inner, type_args, method_args, generics)
            }

            // Ptr — unwrap and return inner token
            TypeSignature::Ptr(ptr) => {
                self.type_signature_to_token(&ptr.base, type_args, method_args, generics)
            }

            // Pinned and modified types — unwrap and return inner token
            TypeSignature::Pinned(inner)
            | TypeSignature::ModifiedRequired(_, inner)
            | TypeSignature::ModifiedOptional(_, inner) => {
                self.type_signature_to_token(inner, type_args, method_args, generics)
            }

            // Types that don't map cleanly to a single token
            _ => None,
        }
    }

    /// Substitutes generic type parameters in a method signature.
    ///
    /// Walks the method's parameter and return type signatures, replacing
    /// `GenericParamType(n)` with `type_args[n]` and `GenericParamMethod(n)`
    /// with `method_args[n]`. This is needed for correct signature matching
    /// when dispatching generic method instantiations.
    ///
    /// # Arguments
    ///
    /// * `sig` - The method signature to substitute
    /// * `type_args` - Type-level generic arguments (`!0`, `!1`, ...)
    /// * `method_args` - Method-level generic arguments (`!!0`, `!!1`, ...)
    #[must_use]
    pub fn substitute_generic_params(
        sig: &SignatureMethod,
        type_args: Option<&[Token]>,
        method_args: Option<&[Token]>,
    ) -> SignatureMethod {
        let substitute_type_sig = |ts: &TypeSignature| -> TypeSignature {
            Self::substitute_type_signature(ts, type_args, method_args)
        };

        let new_params: Vec<SignatureParameter> = sig
            .params
            .iter()
            .map(|p| SignatureParameter {
                base: substitute_type_sig(&p.base),
                by_ref: p.by_ref,
                modifiers: p.modifiers.clone(),
            })
            .collect();

        let new_return = SignatureParameter {
            base: substitute_type_sig(&sig.return_type.base),
            by_ref: sig.return_type.by_ref,
            modifiers: sig.return_type.modifiers.clone(),
        };

        let new_varargs: Vec<SignatureParameter> = sig
            .varargs
            .iter()
            .map(|p| SignatureParameter {
                base: substitute_type_sig(&p.base),
                by_ref: p.by_ref,
                modifiers: p.modifiers.clone(),
            })
            .collect();

        let mut result = sig.clone();
        result.return_type = new_return;
        result.params = new_params;
        result.varargs = new_varargs;
        result
    }

    /// Substitutes generic parameters in a single type signature.
    fn substitute_type_signature(
        sig: &TypeSignature,
        type_args: Option<&[Token]>,
        method_args: Option<&[Token]>,
    ) -> TypeSignature {
        match sig {
            TypeSignature::GenericParamType(index) => {
                if let Some(token) = type_args.and_then(|args| args.get(*index as usize)) {
                    TypeSignature::Class(*token)
                } else {
                    sig.clone()
                }
            }
            TypeSignature::GenericParamMethod(index) => {
                if let Some(token) = method_args.and_then(|args| args.get(*index as usize)) {
                    TypeSignature::Class(*token)
                } else {
                    sig.clone()
                }
            }
            TypeSignature::GenericInst(base, args) => {
                let new_base = Self::substitute_type_signature(base, type_args, method_args);
                let new_args: Vec<TypeSignature> = args
                    .iter()
                    .map(|a| Self::substitute_type_signature(a, type_args, method_args))
                    .collect();
                TypeSignature::GenericInst(Box::new(new_base), new_args)
            }
            TypeSignature::SzArray(sz) => {
                let new_elem = Self::substitute_type_signature(&sz.base, type_args, method_args);
                TypeSignature::SzArray(SignatureSzArray {
                    base: Box::new(new_elem),
                    modifiers: sz.modifiers.clone(),
                })
            }
            TypeSignature::ByRef(inner) => TypeSignature::ByRef(Box::new(
                Self::substitute_type_signature(inner, type_args, method_args),
            )),
            TypeSignature::Pinned(inner) => TypeSignature::Pinned(Box::new(
                Self::substitute_type_signature(inner, type_args, method_args),
            )),
            TypeSignature::Ptr(ptr) => TypeSignature::Ptr(SignaturePointer {
                modifiers: ptr.modifiers.clone(),
                base: Box::new(Self::substitute_type_signature(
                    &ptr.base,
                    type_args,
                    method_args,
                )),
            }),
            TypeSignature::Array(array) => TypeSignature::Array(SignatureArray {
                base: Box::new(Self::substitute_type_signature(
                    &array.base,
                    type_args,
                    method_args,
                )),
                rank: array.rank,
                dimensions: array.dimensions.clone(),
            }),
            TypeSignature::FnPtr(method) => TypeSignature::FnPtr(Box::new(
                Self::substitute_generic_params(method, type_args, method_args),
            )),
            TypeSignature::ModifiedRequired(modifiers, base) => TypeSignature::ModifiedRequired(
                modifiers.clone(),
                Box::new(Self::substitute_type_signature(
                    base,
                    type_args,
                    method_args,
                )),
            ),
            TypeSignature::ModifiedOptional(modifiers, base) => TypeSignature::ModifiedOptional(
                modifiers.clone(),
                Box::new(Self::substitute_type_signature(
                    base,
                    type_args,
                    method_args,
                )),
            ),
            _ => sig.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::signatures::CustomModifier;

    fn param(base: TypeSignature) -> SignatureParameter {
        SignatureParameter {
            modifiers: Vec::new(),
            by_ref: false,
            base,
        }
    }

    /// Generic parameters are substituted wherever they are nested: pointers, general arrays,
    /// function pointers, modified types and varargs as well as the simpler shapes.
    #[test]
    fn substitution_reaches_every_nested_type() {
        let (a, b, c) = (
            Token::new(0x0200_0001),
            Token::new(0x0200_0002),
            Token::new(0x0200_0003),
        );
        let modifier = CustomModifier {
            is_required: true,
            modifier_type: Token::new(0x0100_0009),
        };
        let shapes = |t: TypeSignature, m: TypeSignature, t1: TypeSignature| {
            vec![
                param(TypeSignature::Ptr(SignaturePointer {
                    modifiers: Vec::new(),
                    base: Box::new(t.clone()),
                })),
                param(TypeSignature::Array(SignatureArray {
                    base: Box::new(m.clone()),
                    rank: 2,
                    dimensions: Vec::new(),
                })),
                param(TypeSignature::FnPtr(Box::new(SignatureMethod {
                    return_type: param(t.clone()),
                    ..SignatureMethod::default()
                }))),
                param(TypeSignature::GenericInst(
                    Box::new(TypeSignature::Class(Token::new(0x0100_0008))),
                    vec![TypeSignature::ModifiedRequired(
                        vec![modifier.clone()],
                        Box::new(t1),
                    )],
                )),
            ]
        };
        let signature = SignatureMethod {
            params: shapes(
                TypeSignature::GenericParamType(0),
                TypeSignature::GenericParamMethod(0),
                TypeSignature::GenericParamType(1),
            ),
            varargs: vec![param(TypeSignature::GenericParamType(1))],
            ..SignatureMethod::default()
        };
        let substituted =
            EmulationContext::substitute_generic_params(&signature, Some(&[a, b]), Some(&[c]));
        assert_eq!(
            substituted.params,
            shapes(
                TypeSignature::Class(a),
                TypeSignature::Class(c),
                TypeSignature::Class(b),
            )
        );
        assert_eq!(substituted.varargs, vec![param(TypeSignature::Class(b))]);
    }
}

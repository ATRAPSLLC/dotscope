//! Re-export shim: generic SSA ops live in `analyssa::ir::ops`.
//!
//! The CIL-specific methods live here as the [`SsaOpCilExt`] extension trait
//! (orphan rule prevents inherent impls on foreign types), beside the CIL
//! prefixes ([`CilPrefix`]) the lift states on the operations they prefix.

use std::num::NonZeroU8;

// `BinaryOpInfo`/`UnaryOpInfo` aren't re-exported (the original dotscope
// `ops.rs` didn't surface them either; direct callers go through
// `analyssa::ir::ops` if they need them).
pub use analyssa::ir::ops::{
    AccessQualifiers, BinaryOpKind, BreakpointOp, CmpKind, RuntimeValueKind, UnaryOpKind,
};
use analyssa::ir::ops::{Reference, SsaOp as AnalyssaSsaOp};

use crate::{
    analysis::ssa::{target::CilTarget, types::TypeRef},
    metadata::token::Token,
    Error, Result,
};

/// CIL-defaulted alias of `analyssa::ir::ops::SsaOp`.
pub type SsaOp<T = CilTarget> = AnalyssaSsaOp<T>;

/// CIL-defaulted alias of `analyssa::ir::CallData`.
pub type CallData<T = CilTarget> = analyssa::ir::CallData<T>;

/// CIL-defaulted alias of `analyssa::ir::Callee`.
pub type Callee<T = CilTarget> = analyssa::ir::Callee<T>;

/// CIL-specific extension methods on `SsaOp<CilTarget>`.
///
/// Import this trait to call `op.referenced_tokens()` or `op.method_call()`.
pub trait SsaOpCilExt {
    /// The metadata tokens this operation references, every one its code
    /// writes ([`SsaOp::visit_references`]): methods, fields, types (those its
    /// host types name too), and an indirect call's signature.
    ///
    /// Used for cleanup operations to identify which SSA operations reference
    /// tokens that are being removed.
    fn referenced_tokens(&self) -> impl Iterator<Item = Token>;

    /// The call this operation is when it names its method (a direct,
    /// virtual or constrained call), with that method's token; `None` for a
    /// call through a pointer and every other operation.
    fn method_call(&self) -> Option<(Token, &CallData)>;
}

impl SsaOpCilExt for AnalyssaSsaOp<CilTarget> {
    fn method_call(&self) -> Option<(Token, &CallData)> {
        let call = self.as_call()?;
        Some((call.callee.method()?.token(), call))
    }

    fn referenced_tokens(&self) -> impl Iterator<Item = Token> {
        let mut tokens = Vec::new();
        self.visit_references(|reference| match reference {
            Reference::Type(type_ref) => tokens.push(type_ref.token()),
            Reference::Method(method) => tokens.push(method.token()),
            Reference::Field(field) => tokens.push(field.token()),
            Reference::Signature(signature) => tokens.push(signature.token()),
            // CIL names no symbols.
            Reference::Symbol(_) => {}
            Reference::HostType(ty) => ty.visit_tokens(&mut |token| tokens.push(token)),
        });
        tokens.into_iter()
    }
}

/// A CIL prefix: an instruction that changes how the one after it is made
/// (ECMA-335 III.2). The lift states each on the operation it prefixes
/// ([`Self::apply`]), and code generation writes them back before it
/// ([`Self::of`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CilPrefix {
    /// `unaligned.`: the address may be aligned to only this many bytes.
    Unaligned(NonZeroU8),
    /// `volatile.`: the access is made exactly as written.
    Volatile,
    /// `readonly.`: the element address is never written through.
    Readonly,
    /// `constrained.`: the virtual call's receiver is the address of a value
    /// of this type.
    Constrained(TypeRef),
    /// `tail.`: the call is a tail call.
    Tail,
}

impl CilPrefix {
    /// States this prefix on `op`, the instruction it prefixes: the access
    /// qualifiers of a memory access (`volatile.`, `unaligned.`), a call's
    /// tail call (`tail.`), a virtual call's constraint (`constrained.`), an
    /// element address's read-only use (`readonly.`).
    ///
    /// # Errors
    ///
    /// [`Error::SsaError`] where `op` is no instruction the prefix may prefix,
    /// which the IL does not allow.
    pub fn apply(self, op: &mut SsaOp) -> Result<()> {
        let mut stated = false;
        let applied = match &self {
            // A static field is always aligned: `unaligned.` prefixes the
            // accesses through an address and of instance fields only.
            Self::Unaligned(_)
                if matches!(
                    op,
                    SsaOp::LoadStaticField { .. } | SsaOp::StoreStaticField { .. }
                ) =>
            {
                false
            }
            Self::Unaligned(bytes) => {
                op.visit_qualifiers_mut(|qualifiers| {
                    qualifiers.alignment = Some(*bytes);
                    stated = true;
                });
                stated
            }
            Self::Volatile => {
                op.visit_qualifiers_mut(|qualifiers| {
                    qualifiers.volatile = true;
                    stated = true;
                });
                stated
            }
            Self::Readonly => match op {
                SsaOp::LoadElementAddr { readonly, .. } => {
                    *readonly = true;
                    true
                }
                _ => false,
            },
            // `constrained. callvirt` of an instance method; `constrained.
            // call` and `constrained. ldftn` of a static virtual one.
            Self::Constrained(constraint_type) => match op {
                SsaOp::Call(call) => match &call.callee {
                    &Callee::Virtual(method) | &Callee::Direct(method) => {
                        call.callee = Callee::Constrained {
                            method,
                            constraint_type: *constraint_type,
                            instance: matches!(call.callee, Callee::Virtual(_)),
                        };
                        true
                    }
                    Callee::Constrained { .. } | Callee::Indirect { .. } => false,
                },
                SsaOp::LoadFunctionPtr { constraint, .. } if constraint.is_none() => {
                    *constraint = Some(*constraint_type);
                    true
                }
                _ => false,
            },
            Self::Tail => match op.as_call_mut() {
                Some(call) => {
                    call.tail = true;
                    true
                }
                None => false,
            },
        };
        if applied {
            Ok(())
        } else {
            Err(Error::SsaError(format!("{self:?} cannot prefix {op}")))
        }
    }

    /// The prefixes `op` states, in the order they are written before it:
    /// `unaligned.` and `volatile.` of its access, `readonly.`, then a call's
    /// or a function pointer's `constrained.` and a call's `tail.`, which
    /// must immediately precede it.
    #[must_use]
    pub fn of(op: &SsaOp) -> Vec<Self> {
        let (mut alignment, mut volatile) = (None, false);
        op.visit_qualifiers(|qualifiers| {
            alignment = alignment.or(qualifiers.alignment);
            volatile |= qualifiers.volatile;
        });
        let mut prefixes: Vec<Self> = alignment.map(Self::Unaligned).into_iter().collect();
        if volatile {
            prefixes.push(Self::Volatile);
        }
        if matches!(op, SsaOp::LoadElementAddr { readonly: true, .. }) {
            prefixes.push(Self::Readonly);
        }
        if let SsaOp::LoadFunctionPtr {
            constraint: Some(constraint_type),
            ..
        } = op
        {
            prefixes.push(Self::Constrained(*constraint_type));
        }
        if let Some(call) = op.as_call() {
            if let Callee::Constrained {
                constraint_type, ..
            } = &call.callee
            {
                prefixes.push(Self::Constrained(*constraint_type));
            }
            if call.tail {
                prefixes.push(Self::Tail);
            }
        }
        prefixes
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU8;

    use crate::{
        analysis::ssa::{
            ops::{
                AccessQualifiers, BinaryOpKind, CallData, Callee, CilPrefix, SsaOpCilExt,
                UnaryOpKind,
            },
            target::CilTarget,
            types::{FieldRef, MethodRef, SigRef, SsaType, TypeRef},
            value::ConstValue as RawConstValue,
            SsaVarId,
        },
        metadata::token::Token,
    };

    // Lock the type parameter to CilTarget for the test module so unit-only
    // variant constructions like `SsaOp::Add { ... }` infer cleanly.
    type SsaOp = super::SsaOp<CilTarget>;
    type ConstValue = RawConstValue<CilTarget>;

    #[test]
    fn test_dest_extraction() {
        let dest = SsaVarId::from_index(0);
        let left = SsaVarId::from_index(1);
        let right = SsaVarId::from_index(2);
        let op = SsaOp::Add {
            dest,
            left,
            right,
            flags: None,
        };
        assert_eq!(op.dest(), Some(dest));

        let op = SsaOp::Jump { target: 1 };
        assert_eq!(op.dest(), None);

        let call_dest = SsaVarId::from_index(3);
        let method = || Callee::Direct(MethodRef::new(Token::new(0x06000001)));
        let op: SsaOp = CallData::new(Some(call_dest), method(), vec![]).into();
        assert_eq!(op.dest(), Some(call_dest));

        let op: SsaOp = CallData::new(None, method(), vec![]).into();
        assert_eq!(op.dest(), None);
    }

    #[test]
    fn test_uses_extraction() {
        let dest = SsaVarId::from_index(0);
        let left = SsaVarId::from_index(1);
        let right = SsaVarId::from_index(2);
        let op = SsaOp::Add {
            dest,
            left,
            right,
            flags: None,
        };
        assert_eq!(op.uses(), vec![left, right]);

        let const_dest = SsaVarId::from_index(3);
        let op = SsaOp::Const {
            dest: const_dest,
            value: ConstValue::I32(42),
        };
        assert!(op.uses().is_empty());

        let phi_dest = SsaVarId::from_index(4);
        let phi_op1 = SsaVarId::from_index(5);
        let phi_op2 = SsaVarId::from_index(6);
        let op = SsaOp::Phi {
            dest: phi_dest,
            operands: vec![(0, phi_op1), (1, phi_op2)],
        };
        assert_eq!(op.uses(), vec![phi_op1, phi_op2]);
    }

    #[test]
    fn test_is_terminator() {
        let cond = SsaVarId::from_index(0);
        let exc = SsaVarId::from_index(1);
        let dest = SsaVarId::from_index(2);
        let left = SsaVarId::from_index(3);
        let right = SsaVarId::from_index(4);

        assert!(SsaOp::Jump { target: 1 }.is_terminator());
        assert!(SsaOp::Branch {
            condition: cond,
            true_target: 1,
            false_target: 2
        }
        .is_terminator());
        assert!(SsaOp::returns(None).is_terminator());
        assert!(SsaOp::Throw { exception: exc }.is_terminator());

        assert!(!SsaOp::Nop.is_terminator());
        assert!(!SsaOp::Add {
            dest,
            left,
            right,
            flags: None
        }
        .is_terminator());
    }

    #[test]
    fn test_is_pure() {
        let dest = SsaVarId::from_index(0);
        let left = SsaVarId::from_index(1);
        let right = SsaVarId::from_index(2);
        let const_dest = SsaVarId::from_index(3);
        let object = SsaVarId::from_index(4);
        let value = SsaVarId::from_index(5);

        assert!(SsaOp::Add {
            dest,
            left,
            right,
            flags: None
        }
        .is_pure());
        assert!(SsaOp::Const {
            dest: const_dest,
            value: ConstValue::I32(42)
        }
        .is_pure());
        assert!(SsaOp::Nop.is_pure());

        // Not pure: has side effects
        assert!(!SsaOp::StoreField {
            object,
            field: FieldRef::new(Token::new(0x04000001)),
            value,
            access: AccessQualifiers::FLAT,
        }
        .is_pure());
        let call: SsaOp = CallData::new(
            None,
            Callee::Direct(MethodRef::new(Token::new(0x06000001))),
            vec![],
        )
        .into();
        assert!(!call.is_pure());
    }

    fn method() -> MethodRef {
        MethodRef::new(Token::new(0x0600_0001))
    }

    fn load_field() -> SsaOp {
        SsaOp::LoadField {
            dest: SsaVarId::from_index(0),
            object: SsaVarId::from_index(1),
            field: FieldRef::new(Token::new(0x0400_0001)),
            access: AccessQualifiers::FLAT,
        }
    }

    fn call(callee: Callee) -> SsaOp {
        CallData::new(None, callee, vec![SsaVarId::from_index(1)]).into()
    }

    /// **A prefix is stated on the operation it prefixes, and read back from
    /// it.** `volatile.` and `unaligned.` qualify the access, `readonly.` the
    /// element address, `constrained.` turns a virtual call constrained and
    /// `tail.` makes a call a tail call; [`CilPrefix::of`] then names them
    /// again, in the order they are written.
    #[test]
    fn a_prefix_is_stated_on_the_operation_it_prefixes() {
        let two = NonZeroU8::new(2).unwrap();
        let constraint = TypeRef::new(Token::new(0x0200_0003));
        let element_address = SsaOp::LoadElementAddr {
            dest: SsaVarId::from_index(0),
            array: SsaVarId::from_index(1),
            index: SsaVarId::from_index(2),
            elem_type: constraint,
            readonly: false,
        };
        let cases = [
            (
                load_field(),
                vec![CilPrefix::Unaligned(two), CilPrefix::Volatile],
            ),
            (element_address, vec![CilPrefix::Readonly]),
            (
                call(Callee::Virtual(method())),
                vec![CilPrefix::Constrained(constraint), CilPrefix::Tail],
            ),
            (call(Callee::Direct(method())), vec![CilPrefix::Tail]),
            (
                call(Callee::Direct(method())),
                vec![CilPrefix::Constrained(constraint)],
            ),
            (
                SsaOp::LoadFunctionPtr {
                    dest: SsaVarId::from_index(0),
                    method: method(),
                    constraint: None,
                },
                vec![CilPrefix::Constrained(constraint)],
            ),
        ];
        for (mut op, prefixes) in cases {
            assert!(CilPrefix::of(&op).is_empty(), "{op} states nothing yet");
            // Written in the other order: what is read back is the order
            // the IL takes them in.
            for prefix in prefixes.iter().rev() {
                prefix.apply(&mut op).unwrap();
            }
            assert_eq!(CilPrefix::of(&op), prefixes, "{op}");
        }

        let mut op = load_field();
        CilPrefix::Volatile.apply(&mut op).unwrap();
        assert!(op.is_volatile());
        // `constrained. callvirt` calls an instance method through the
        // receiver's address; `constrained. call` a static virtual one.
        for (callee, instance) in [
            (Callee::Virtual(method()), true),
            (Callee::Direct(method()), false),
        ] {
            let mut op = call(callee);
            CilPrefix::Constrained(constraint).apply(&mut op).unwrap();
            assert_eq!(
                op.as_call().map(|call| &call.callee),
                Some(&Callee::Constrained {
                    method: method(),
                    constraint_type: constraint,
                    instance,
                })
            );
        }
    }

    /// A prefix on an instruction the IL does not let it prefix is an error,
    /// not a prefix silently dropped.
    #[test]
    fn a_prefix_on_what_it_may_not_prefix_is_an_error() {
        let one = NonZeroU8::new(1).unwrap();
        let add = SsaOp::Add {
            dest: SsaVarId::from_index(0),
            left: SsaVarId::from_index(1),
            right: SsaVarId::from_index(2),
            flags: None,
        };
        let static_load = SsaOp::LoadStaticField {
            dest: SsaVarId::from_index(0),
            field: FieldRef::new(Token::new(0x0400_0001)),
            access: AccessQualifiers::FLAT,
        };
        let constraint = TypeRef::new(Token::new(0x0200_0003));
        let cases = [
            (CilPrefix::Volatile, add.clone()),
            (CilPrefix::Unaligned(one), add.clone()),
            (CilPrefix::Unaligned(one), static_load.clone()),
            (CilPrefix::Readonly, load_field()),
            (CilPrefix::Tail, add),
            (
                CilPrefix::Constrained(constraint),
                call(Callee::Indirect {
                    fptr: SsaVarId::from_index(2),
                    signature: SigRef::new(Token::new(0x1100_0001)),
                }),
            ),
            (CilPrefix::Constrained(constraint), load_field()),
        ];
        for (prefix, mut op) in cases {
            let before = op.clone();
            assert!(prefix.apply(&mut op).is_err(), "{prefix:?} on {op}");
            assert_eq!(op, before, "a rejected {prefix:?} leaves {op} as it was");
        }
        // `volatile.` does prefix a static field access.
        let mut op = static_load;
        CilPrefix::Volatile.apply(&mut op).unwrap();
        assert!(op.is_volatile());
    }

    /// **An operation references every token its code writes.** A call names
    /// its method and a constrained call its constraint type too; a call
    /// through a pointer names its standalone signature and no method; a
    /// handle constant and a typed reference name what they hold; an element
    /// access names the types its element type is built of.
    #[test]
    fn an_operation_references_every_token_its_code_writes() {
        let tokens = |op: &SsaOp| op.referenced_tokens().collect::<Vec<_>>();
        let constraint = TypeRef::new(Token::new(0x0200_0003));
        let constrained = call(Callee::Constrained {
            method: method(),
            constraint_type: constraint,
            instance: true,
        });
        assert_eq!(tokens(&constrained), [method().token(), constraint.token()]);
        assert_eq!(
            constrained.method_call().map(|(token, _)| token),
            Some(method().token())
        );
        let signature = Token::new(0x1100_0001);
        let indirect = call(Callee::Indirect {
            fptr: SsaVarId::from_index(2),
            signature: SigRef::new(signature),
        });
        assert_eq!(tokens(&indirect), [signature]);
        assert!(indirect.method_call().is_none());
        assert_eq!(tokens(&load_field()), [Token::new(0x0400_0001)]);

        let field = Token::new(0x0400_0002);
        let handle = SsaOp::Const {
            dest: SsaVarId::from_index(0),
            value: ConstValue::FieldHandle(FieldRef::new(field)),
        };
        assert_eq!(tokens(&handle), [field]);
        let typed_ref = SsaOp::MakeTypedRef {
            dest: SsaVarId::from_index(0),
            address: SsaVarId::from_index(1),
            value_type: constraint,
        };
        assert_eq!(tokens(&typed_ref), [constraint.token()]);
        let (generic, argument) = (Token::new(0x0100_0004), Token::new(0x0200_0005));
        let element = SsaOp::LoadElement {
            dest: SsaVarId::from_index(0),
            array: SsaVarId::from_index(1),
            index: SsaVarId::from_index(2),
            elem_type: SsaType::GenericInst(
                Box::new(SsaType::ValueType(TypeRef::new(generic))),
                vec![SsaType::Class(TypeRef::new(argument)), SsaType::I32],
            ),
        };
        assert_eq!(tokens(&element), [generic, argument]);
    }

    #[test]
    fn test_display() {
        let op = SsaOp::Add {
            dest: SsaVarId::from_index(2),
            left: SsaVarId::from_index(0),
            right: SsaVarId::from_index(1),
            flags: None,
        };
        assert_eq!(format!("{op}"), "v2 = add v0, v1");

        let op = SsaOp::Const {
            dest: SsaVarId::from_index(0),
            value: ConstValue::I32(42),
        };
        assert_eq!(format!("{op}"), "v0 = 42");

        let op = SsaOp::Branch {
            condition: SsaVarId::from_index(0),
            true_target: 1,
            false_target: 2,
        };
        assert_eq!(format!("{op}"), "branch v0, B1, B2");

        let op = SsaOp::Phi {
            dest: SsaVarId::from_index(3),
            operands: vec![(0, SsaVarId::from_index(1)), (1, SsaVarId::from_index(2))],
        };
        assert_eq!(format!("{op}"), "v3 = phi(B0: v1, B1: v2)");
    }

    #[test]
    fn test_successors() {
        let cond = SsaVarId::from_index(0);
        let switch_val = SsaVarId::from_index(1);
        let ret_val = SsaVarId::from_index(2);
        let exc = SsaVarId::from_index(3);
        let dest = SsaVarId::from_index(4);
        let left = SsaVarId::from_index(5);
        let right = SsaVarId::from_index(6);

        // Jump has single successor
        let op = SsaOp::Jump { target: 5 };
        assert_eq!(op.successors(), vec![5]);

        // Leave has single successor
        let op = SsaOp::Leave { target: 3 };
        assert_eq!(op.successors(), vec![3]);

        // Branch has two successors
        let op = SsaOp::Branch {
            condition: cond,
            true_target: 1,
            false_target: 2,
        };
        assert_eq!(op.successors(), vec![1, 2]);

        // Switch has multiple successors plus default
        let op = SsaOp::Switch {
            value: switch_val,
            targets: vec![1, 2, 3],
            default: 4,
        };
        assert_eq!(op.successors(), vec![1, 2, 3, 4]);

        // Return has no successors
        let op = SsaOp::returns(None);
        assert!(op.successors().is_empty());

        let op = SsaOp::returns(Some(ret_val));
        assert!(op.successors().is_empty());

        // Throw has no successors
        let op = SsaOp::Throw { exception: exc };
        assert!(op.successors().is_empty());

        // Non-terminators have no successors
        let op = SsaOp::Add {
            dest,
            left,
            right,
            flags: None,
        };
        assert!(op.successors().is_empty());

        let op = SsaOp::Nop;
        assert!(op.successors().is_empty());
    }

    #[test]
    fn test_as_binary_op() {
        let dest = SsaVarId::from_index(0);
        let left = SsaVarId::from_index(1);
        let right = SsaVarId::from_index(2);

        // Add is a binary operation
        let op = SsaOp::Add {
            dest,
            left,
            right,
            flags: None,
        };
        let info = op.as_binary_op().expect("Add should be binary op");
        assert_eq!(info.kind, BinaryOpKind::Add);
        assert_eq!(info.dest, dest);
        assert_eq!(info.left, left);
        assert_eq!(info.right, right);
        assert!(!info.unsigned);

        // Div with unsigned
        let op = SsaOp::Div {
            dest,
            left,
            right,
            unsigned: true,
            flags: None,
        };
        let info = op.as_binary_op().expect("Div should be binary op");
        assert_eq!(info.kind, BinaryOpKind::Div);
        assert!(info.unsigned);

        // Shl maps value/amount to left/right
        let value = SsaVarId::from_index(3);
        let amount = SsaVarId::from_index(4);
        let op = SsaOp::Shl {
            dest,
            value,
            amount,
            flags: None,
        };
        let info = op.as_binary_op().expect("Shl should be binary op");
        assert_eq!(info.kind, BinaryOpKind::Shl);
        assert_eq!(info.left, value);
        assert_eq!(info.right, amount);

        // Comparison operations
        let op = SsaOp::Clt {
            dest,
            left,
            right,
            unsigned: true,
            signaling: false,
        };
        let info = op.as_binary_op().expect("Clt should be binary op");
        assert_eq!(info.kind, BinaryOpKind::Clt);
        assert!(info.unsigned);

        // Non-binary operations return None
        assert!(SsaOp::Nop.as_binary_op().is_none());
        assert!(SsaOp::Jump { target: 1 }.as_binary_op().is_none());
        assert!(SsaOp::Neg {
            dest,
            operand: left,
            flags: None,
        }
        .as_binary_op()
        .is_none());
        assert!(SsaOp::Const {
            dest,
            value: ConstValue::I32(42)
        }
        .as_binary_op()
        .is_none());
    }

    #[test]
    fn test_as_unary_op() {
        let dest = SsaVarId::from_index(0);
        let operand = SsaVarId::from_index(1);

        // Neg is a unary operation
        let op = SsaOp::Neg {
            dest,
            operand,
            flags: None,
        };
        let info = op.as_unary_op().expect("Neg should be unary op");
        assert_eq!(info.kind, UnaryOpKind::Neg);
        assert_eq!(info.dest, dest);
        assert_eq!(info.operand, operand);

        // Not is a unary operation
        let op = SsaOp::Not {
            dest,
            operand,
            flags: None,
        };
        let info = op.as_unary_op().expect("Not should be unary op");
        assert_eq!(info.kind, UnaryOpKind::Not);

        // Ckfinite is a unary operation
        let op = SsaOp::Ckfinite { dest, operand };
        let info = op.as_unary_op().expect("Ckfinite should be unary op");
        assert_eq!(info.kind, UnaryOpKind::Ckfinite);

        // Non-unary operations return None
        assert!(SsaOp::Nop.as_unary_op().is_none());
        assert!(SsaOp::Jump { target: 1 }.as_unary_op().is_none());

        let left = SsaVarId::from_index(2);
        let right = SsaVarId::from_index(3);
        assert!(SsaOp::Add {
            dest,
            left,
            right,
            flags: None
        }
        .as_unary_op()
        .is_none());

        assert!(SsaOp::Const {
            dest,
            value: ConstValue::I32(42)
        }
        .as_unary_op()
        .is_none());
    }

    #[test]
    fn test_binary_op_kind_display() {
        assert_eq!(format!("{}", BinaryOpKind::Add), "add");
        assert_eq!(format!("{}", BinaryOpKind::AddOvf), "add.ovf");
        assert_eq!(format!("{}", BinaryOpKind::Ceq), "ceq");
        assert_eq!(format!("{}", BinaryOpKind::Shl), "shl");
    }

    #[test]
    fn test_unary_op_kind_display() {
        assert_eq!(format!("{}", UnaryOpKind::Neg), "neg");
        assert_eq!(format!("{}", UnaryOpKind::Not), "not");
        assert_eq!(format!("{}", UnaryOpKind::Ckfinite), "ckfinite");
    }
}

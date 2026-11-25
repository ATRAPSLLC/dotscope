//! What this crate knows about an SSA value that the IR does not say.
//!
//! Constant propagation proves a value is a particular constant; a decryptor
//! proves the same about the string a call returns. That knowledge is not in
//! the instruction - a `call` is still a call - so it has to be carried
//! alongside.
//!
//! Carried *in* the value, through [`analyssa::facts::VariableFacts`], rather
//! than in a table keyed by [`SsaVarId`](analyssa::ir::SsaVarId) beside the
//! function. The difference is not bookkeeping. A pass renumbers variables:
//! global value numbering replaces one value with another and reconstruction
//! mints fresh ids for every renamed definition. A table keyed by id then
//! describes whichever value inherited the key - and the fact "this is the
//! constant 0" gets re-pointed at a loop phi that is nothing of the sort. That
//! is not hypothetical: it is how a ConfuserEx dispatcher folded to a constant
//! and turned a method into an infinite loop.
//!
//! Facts in the IR move with the value. They are cloned with the function,
//! restored when a pass group rolls back, and (the part a side table cannot
//! do) carried across the moments where one value becomes another, with this
//! module stating what survives each.

use analyssa::facts::{Derivation, Join, Substitution, VariableFacts};

use crate::analysis::ssa::value::ConstValue;

/// What this crate knows about one SSA value.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CilVariableFacts {
    /// The constant this value is known to hold.
    ///
    /// Written by constant propagation and by the decryptors, which prove a
    /// call returns a particular string. Read by every pass that needs a value
    /// rather than an expression: switch dispatch, opaque predicates, the
    /// decryptors' own argument resolution.
    known_value: Option<ConstValue>,
}

impl CilVariableFacts {
    /// Facts for a value known to hold `value`.
    ///
    /// # Arguments
    ///
    /// * `value` - The constant the value holds.
    #[must_use]
    pub const fn known(value: ConstValue) -> Self {
        Self {
            known_value: Some(value),
        }
    }

    /// The constant this value is known to hold, if any.
    #[must_use]
    pub const fn known_value(&self) -> Option<&ConstValue> {
        self.known_value.as_ref()
    }

    /// Records that this value holds `value`.
    ///
    /// # Arguments
    ///
    /// * `value` - The constant the value holds.
    pub fn set_known_value(&mut self, value: ConstValue) {
        self.known_value = Some(value);
    }

    /// Forgets what this value was known to hold.
    pub fn clear_known_value(&mut self) {
        self.known_value = None;
    }
}

impl VariableFacts for CilVariableFacts {
    /// A derived value stands for its parent, so it holds what its parent held.
    ///
    /// True for every cause. A rename is the same value under a new id; a loop
    /// split, a block duplication and a threaded reconstruction each produce a
    /// value that equals the parent on the path it exists on. A constant is a
    /// constant on every path, which is what makes this total where a fact
    /// about *storage* would not be.
    fn derive(parent: &Self, cause: Derivation) -> Self {
        let _ = cause;
        parent.clone()
    }

    /// A merge is known only when every operand is known and they agree.
    ///
    /// The meet: a phi holds one of its operands, so it is a particular
    /// constant exactly when there is no operand it could be that is anything
    /// else. An empty merge - a phi with no operands - knows nothing rather
    /// than everything.
    fn join(operands: &mut dyn Iterator<Item = &Self>, cause: Join) -> Self {
        let _ = cause;
        let mut agreed: Option<ConstValue> = None;
        for operand in operands {
            match (&agreed, operand.known_value()) {
                (_, None) => return Self::default(),
                (None, Some(value)) => agreed = Some(value.clone()),
                (Some(seen), Some(value)) if seen == value => {}
                (Some(_), Some(_)) => return Self::default(),
            }
        }
        Self {
            known_value: agreed,
        }
    }

    /// The survivor of a substitution keeps its own answer, and takes the
    /// replaced value's where it has none.
    ///
    /// A substitution says the two values compute the same thing, so a
    /// constant either knew already or learns it here. Keeping the survivor's
    /// where both are known matters for the case where they disagree: that is a
    /// defect in whichever pass proved one of them, and adopting the replaced
    /// value would move the damage rather than contain it.
    fn absorb(&mut self, replaced: &Self, cause: Substitution) {
        let _ = cause;
        if self.known_value.is_none() {
            self.known_value = replaced.known_value.clone();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_derived_value_holds_what_its_parent_held() {
        let parent = CilVariableFacts::known(ConstValue::I32(7));
        for cause in [
            Derivation::Rename,
            Derivation::BlockDuplication,
            Derivation::LoopSplit,
            Derivation::Reconstruction,
        ] {
            assert_eq!(
                CilVariableFacts::derive(&parent, cause).known_value(),
                Some(&ConstValue::I32(7)),
                "{cause:?}"
            );
        }
    }

    #[test]
    fn a_merge_is_known_only_when_its_operands_agree() {
        let five = CilVariableFacts::known(ConstValue::I32(5));
        let six = CilVariableFacts::known(ConstValue::I32(6));
        let unknown = CilVariableFacts::default();

        let agree = [five.clone(), five.clone()];
        assert_eq!(
            CilVariableFacts::join(&mut agree.iter(), Join::PlacedPhi).known_value(),
            Some(&ConstValue::I32(5))
        );

        let disagree = [five.clone(), six];
        assert_eq!(
            CilVariableFacts::join(&mut disagree.iter(), Join::PlacedPhi).known_value(),
            None
        );

        // One unknown operand is enough: the phi may hold it.
        let partial = [five, unknown];
        assert_eq!(
            CilVariableFacts::join(&mut partial.iter(), Join::LoopHeaderPhi).known_value(),
            None,
            "a loop header whose back edge is unknown is not the initial constant"
        );

        // A merge of nothing knows nothing.
        let mut empty = std::iter::empty::<&CilVariableFacts>();
        assert_eq!(
            CilVariableFacts::join(&mut empty, Join::ExceptionRootPhi).known_value(),
            None
        );
    }

    #[test]
    fn a_survivor_learns_only_what_it_did_not_know() {
        let mut unknown = CilVariableFacts::default();
        unknown.absorb(
            &CilVariableFacts::known(ConstValue::I32(3)),
            Substitution::Gvn,
        );
        assert_eq!(unknown.known_value(), Some(&ConstValue::I32(3)));

        let mut known = CilVariableFacts::known(ConstValue::I32(1));
        known.absorb(
            &CilVariableFacts::known(ConstValue::I32(2)),
            Substitution::CopyPropagation,
        );
        assert_eq!(
            known.known_value(),
            Some(&ConstValue::I32(1)),
            "a disagreement is contained, not propagated"
        );
    }
}

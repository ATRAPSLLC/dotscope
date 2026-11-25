//! x86 flags modeling for condition code tracking.
//!
//! This module records which instruction last set the x86 flags, so that the
//! translator can lower a conditional jump, `SETcc` or `CMOVcc` to exactly the
//! condition the flags hold.
//!
//! # Overview
//!
//! x86 uses implicit flags (ZF, SF, OF, CF, PF) set by comparison and arithmetic
//! operations. Conditional jumps test these flags to determine the branch direction.
//!
//! In SSA form this implicit state is replaced by the values it is computed from:
//! - `CMP a, b` (and `SUB a, b`) + `Jcc target` fuses into
//!   `BranchCmp(cmp, a, b, true_target, false_target)`: every condition of the
//!   flags of `a - b` is a comparison of `a` with `b`.
//! - After any other producer, each flag a condition reads is computed from the
//!   producer's result and operands, and the condition is the formula of those
//!   flags in the table below ([`condition_formula`]).
//!
//! # Flag Dependencies
//!
//! | Condition | Flags | Meaning |
//! |-----------|-------|---------|
//! | E/NE | ZF | Equal / Not equal |
//! | L/GE | SF≠OF | Less / Greater-or-equal (signed) |
//! | LE/G | ZF or SF≠OF | Less-or-equal / Greater (signed) |
//! | B/AE | CF | Below / Above-or-equal (unsigned) |
//! | BE/A | CF or ZF | Below-or-equal / Above (unsigned) |
//! | S/NS | SF | Sign / Not sign |
//! | O/NO | OF | Overflow / Not overflow |
//! | P/NP | PF | Parity even / Parity odd |
//!
//! # What is known
//!
//! The state holds a flag only when it is known exactly. An instruction that
//! leaves a flag undefined, or sets it in a way not modelled here, makes it
//! unknown, and a condition that reads an unknown flag cannot be translated: the
//! translation fails rather than branch on a guess. Instructions that do not touch
//! the flags (`MOV`, `LEA`, `PUSH`, `NOT`, ...) leave the state as it is.
//!
//! # Example
//!
//! The `examples::module_example` test in this module runs this example.

use crate::analysis::{
    ssa::{CmpKind, SsaVarId},
    x86::types::X86Condition,
};

/// How the overflow flag of a [`FlagProducer::Result`] is computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultKind {
    /// `ADD`, `ADC`, `INC`, `XADD`: OF is the signed overflow of `left + right`,
    /// `((left ^ result) & (right ^ result))` at the sign bit.
    Add,
    /// `SBB`, `DEC`: OF is the signed overflow of `left - right`,
    /// `((left ^ right) & (left ^ result))` at the sign bit. Unlike `SUB`, the
    /// conditions are not a comparison of the operands: `SBB` subtracts the carry
    /// too, and `DEC` leaves CF as it was.
    Sub,
    /// `AND`, `OR`, `XOR`, `TEST`: OF is 0 (and CF, which the carry records, is 0).
    Logic,
    /// `NEG`: OF is set exactly when the result is the most negative value.
    Neg,
    /// A shift by a count other than zero: OF is defined only for a count of one,
    /// so it is not known.
    Shift,
}

/// What computed the flags the next condition reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagProducer {
    /// `CMP left, right` or `SUB left, right`: the flags of `left - right`.
    ///
    /// Every comparison condition (E, NE, L, GE, LE, G, B, AE, BE, A) is a
    /// comparison of the two operands, signed or unsigned.
    Compare {
        /// Left operand (minuend).
        left: SsaVarId,
        /// Right operand (subtrahend).
        right: SsaVarId,
    },

    /// Any other operation that sets ZF, SF and PF from its result.
    Result {
        /// The operation's result, at the full register width.
        result: SsaVarId,
        /// The left operand, for the overflow flag.
        left: SsaVarId,
        /// The right operand, for the overflow flag.
        right: SsaVarId,
        /// How the overflow flag follows from the operands and the result.
        kind: ResultKind,
    },
}

/// Tracks the current state of x86 flags for SSA translation.
///
/// This state is maintained per basic block during translation. It records
/// the flag producer (ZF, SF, OF and PF follow from it) and, separately, the
/// carry flag as an SSA value, because `INC` and `DEC` set the others and leave
/// CF as it was, and `ADC` and `SBB` read CF as a number.
#[derive(Debug, Clone, Default)]
pub struct FlagState {
    /// The instruction that last set ZF, SF, OF and PF, if they are known.
    producer: Option<FlagProducer>,
    /// The carry flag (CF) as an SSA variable holding 0 or 1, if it is known.
    ///
    /// Set by:
    /// - ADD/ADC/XADD: the carry out of the addition
    /// - SUB/SBB/CMP: the borrow of the subtraction
    /// - AND/OR/XOR/TEST: 0
    /// - NEG: (operand != 0)
    /// - shifts by a count other than zero: the last bit shifted out
    /// - BT: the tested bit
    ///
    /// Preserved by INC and DEC.
    carry: Option<SsaVarId>,
}

impl FlagState {
    /// Creates a new flag state with no known flags.
    #[must_use]
    pub fn new() -> Self {
        Self {
            producer: None,
            carry: None,
        }
    }

    /// Records that `CMP left, right` or `SUB left, right` set the flags.
    ///
    /// # Arguments
    ///
    /// * `left` - SSA variable for the left operand
    /// * `right` - SSA variable for the right operand
    pub fn set_compare(&mut self, left: SsaVarId, right: SsaVarId) {
        self.producer = Some(FlagProducer::Compare { left, right });
    }

    /// Records that an operation of `kind` set ZF, SF, OF and PF from `result`.
    ///
    /// The carry is set separately ([`Self::set_carry`]), or left as it was by
    /// `INC` and `DEC`.
    pub fn set_result(
        &mut self,
        result: SsaVarId,
        left: SsaVarId,
        right: SsaVarId,
        kind: ResultKind,
    ) {
        self.producer = Some(FlagProducer::Result {
            result,
            left,
            right,
            kind,
        });
    }

    /// Makes every flag unknown: the last instruction left them undefined, or set
    /// them in a way not modelled.
    pub fn clear(&mut self) {
        self.producer = None;
        self.carry = None;
    }

    /// Makes ZF, SF, OF and PF unknown and records `carry` as CF: `BT` sets only
    /// CF and leaves the others undefined.
    pub fn set_carry_only(&mut self, carry: SsaVarId) {
        self.producer = None;
        self.carry = Some(carry);
    }

    /// Sets the carry flag to a specific SSA variable (must hold 0 or 1).
    pub fn set_carry(&mut self, carry: SsaVarId) {
        self.carry = Some(carry);
    }

    /// Returns the current carry flag SSA variable, if known.
    #[must_use]
    pub fn carry(&self) -> Option<SsaVarId> {
        self.carry
    }

    /// Returns the current flag producer, if ZF, SF, OF and PF are known.
    #[must_use]
    pub fn producer(&self) -> Option<FlagProducer> {
        self.producer
    }

    /// Returns true if ZF, SF, OF and PF are known.
    #[must_use]
    pub fn is_known(&self) -> bool {
        self.producer.is_some()
    }

    /// The comparison `condition` is, when the flags are those of a `CMP` or
    /// `SUB`: the comparison kind, its two operands, and whether it is unsigned.
    ///
    /// `None` after any other producer, and for S, NS, O, NO, P and NP, which are
    /// no comparison of the operands; those are computed from the flags
    /// ([`condition_formula`]).
    #[must_use]
    pub fn comparison(
        &self,
        condition: X86Condition,
    ) -> Option<(CmpKind, SsaVarId, SsaVarId, bool)> {
        match self.producer? {
            FlagProducer::Compare { left, right } => {
                let (cmp, unsigned) = condition_to_cmp(condition)?;
                Some((cmp, left, right, unsigned))
            }
            FlagProducer::Result { .. } => None,
        }
    }
}

/// The flag formula a condition tests, before its negation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagFormula {
    /// ZF.
    Zero,
    /// SF.
    Sign,
    /// OF.
    Overflow,
    /// PF.
    Parity,
    /// CF.
    Carry,
    /// CF or ZF.
    CarryOrZero,
    /// SF ≠ OF.
    Less,
    /// ZF or SF ≠ OF.
    LessOrEqual,
}

/// The flags `condition` tests: the formula, and whether the condition is its
/// negation (NE is not ZF, AE not CF, A not (CF or ZF), GE not (SF ≠ OF), ...).
#[must_use]
pub const fn condition_formula(condition: X86Condition) -> (FlagFormula, bool) {
    match condition {
        X86Condition::E => (FlagFormula::Zero, false),
        X86Condition::Ne => (FlagFormula::Zero, true),
        X86Condition::S => (FlagFormula::Sign, false),
        X86Condition::Ns => (FlagFormula::Sign, true),
        X86Condition::O => (FlagFormula::Overflow, false),
        X86Condition::No => (FlagFormula::Overflow, true),
        X86Condition::P => (FlagFormula::Parity, false),
        X86Condition::Np => (FlagFormula::Parity, true),
        X86Condition::B => (FlagFormula::Carry, false),
        X86Condition::Ae => (FlagFormula::Carry, true),
        X86Condition::Be => (FlagFormula::CarryOrZero, false),
        X86Condition::A => (FlagFormula::CarryOrZero, true),
        X86Condition::L => (FlagFormula::Less, false),
        X86Condition::Ge => (FlagFormula::Less, true),
        X86Condition::Le => (FlagFormula::LessOrEqual, false),
        X86Condition::G => (FlagFormula::LessOrEqual, true),
    }
}

/// Converts an x86 condition code to an SSA comparison kind.
///
/// Returns the `CmpKind` and a boolean indicating whether the comparison
/// should be unsigned. This is the condition as a comparison of the operands
/// of a `CMP` (or `SUB`), and only of those ([`FlagState::comparison`]).
///
/// # Arguments
///
/// * `condition` - The x86 condition code
///
/// # Returns
///
/// `Some((CmpKind, unsigned))` for the comparison conditions, `None` for
/// S, NS, O, NO, P and NP.
#[must_use]
pub fn condition_to_cmp(condition: X86Condition) -> Option<(CmpKind, bool)> {
    match condition {
        // Equality (works for both signed and unsigned)
        X86Condition::E => Some((CmpKind::Eq, false)),
        X86Condition::Ne => Some((CmpKind::Ne, false)),

        // Signed comparisons
        X86Condition::L => Some((CmpKind::Lt, false)),
        X86Condition::Ge => Some((CmpKind::Ge, false)),
        X86Condition::Le => Some((CmpKind::Le, false)),
        X86Condition::G => Some((CmpKind::Gt, false)),

        // Unsigned comparisons
        X86Condition::B => Some((CmpKind::Lt, true)),
        X86Condition::Ae => Some((CmpKind::Ge, true)),
        X86Condition::Be => Some((CmpKind::Le, true)),
        X86Condition::A => Some((CmpKind::Gt, true)),

        // Sign, overflow and parity are no comparison of the operands
        X86Condition::S
        | X86Condition::Ns
        | X86Condition::O
        | X86Condition::No
        | X86Condition::P
        | X86Condition::Np => None,
    }
}

/// Returns true if the condition tests only the zero flag (ZF).
#[must_use]
pub const fn is_zero_flag_only(condition: X86Condition) -> bool {
    matches!(condition, X86Condition::E | X86Condition::Ne)
}

/// Returns true if the condition uses signed comparison semantics.
#[must_use]
pub const fn is_signed_condition(condition: X86Condition) -> bool {
    matches!(
        condition,
        X86Condition::L | X86Condition::Ge | X86Condition::Le | X86Condition::G
    )
}

/// Returns true if the condition uses unsigned comparison semantics.
#[must_use]
pub const fn is_unsigned_condition(condition: X86Condition) -> bool {
    matches!(
        condition,
        X86Condition::B | X86Condition::Ae | X86Condition::Be | X86Condition::A
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// After a `CMP`, every comparison condition is a comparison of its operands.
    #[test]
    fn a_compare_is_a_comparison_of_its_operands() {
        let mut flags = FlagState::new();
        assert!(!flags.is_known());

        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        flags.set_compare(v0, v1);
        assert!(flags.is_known());

        assert_eq!(
            flags.comparison(X86Condition::L),
            Some((CmpKind::Lt, v0, v1, false))
        );
        assert_eq!(
            flags.comparison(X86Condition::B),
            Some((CmpKind::Lt, v0, v1, true))
        );
        assert_eq!(flags.comparison(X86Condition::S), None);
    }

    /// After any other producer no condition is a comparison of its operands:
    /// `ADD a, b` then `JE` tests the sum, not `a == b`.
    #[test]
    fn a_result_is_no_comparison_of_its_operands() {
        let mut flags = FlagState::new();
        let (result, left, right) = (
            SsaVarId::from_index(0),
            SsaVarId::from_index(1),
            SsaVarId::from_index(2),
        );
        for kind in [
            ResultKind::Add,
            ResultKind::Sub,
            ResultKind::Logic,
            ResultKind::Neg,
            ResultKind::Shift,
        ] {
            flags.set_result(result, left, right, kind);
            for condition in [
                X86Condition::E,
                X86Condition::Ne,
                X86Condition::L,
                X86Condition::B,
                X86Condition::A,
            ] {
                assert_eq!(flags.comparison(condition), None, "{kind:?} {condition:?}");
            }
        }
    }

    #[test]
    fn test_condition_to_cmp() {
        // Equality
        assert_eq!(
            condition_to_cmp(X86Condition::E),
            Some((CmpKind::Eq, false))
        );
        assert_eq!(
            condition_to_cmp(X86Condition::Ne),
            Some((CmpKind::Ne, false))
        );

        // Signed
        assert_eq!(
            condition_to_cmp(X86Condition::L),
            Some((CmpKind::Lt, false))
        );
        assert_eq!(
            condition_to_cmp(X86Condition::G),
            Some((CmpKind::Gt, false))
        );

        // Unsigned
        assert_eq!(condition_to_cmp(X86Condition::B), Some((CmpKind::Lt, true)));
        assert_eq!(condition_to_cmp(X86Condition::A), Some((CmpKind::Gt, true)));

        // No comparison
        assert!(condition_to_cmp(X86Condition::P).is_none());
        assert!(condition_to_cmp(X86Condition::O).is_none());
    }

    /// Each condition and its negation test one formula, as the Intel manual's
    /// condition table states it.
    #[test]
    fn every_condition_tests_its_flags() {
        let table = [
            (X86Condition::E, FlagFormula::Zero, false),
            (X86Condition::Ne, FlagFormula::Zero, true),
            (X86Condition::S, FlagFormula::Sign, false),
            (X86Condition::Ns, FlagFormula::Sign, true),
            (X86Condition::O, FlagFormula::Overflow, false),
            (X86Condition::No, FlagFormula::Overflow, true),
            (X86Condition::P, FlagFormula::Parity, false),
            (X86Condition::Np, FlagFormula::Parity, true),
            (X86Condition::B, FlagFormula::Carry, false),
            (X86Condition::Ae, FlagFormula::Carry, true),
            (X86Condition::Be, FlagFormula::CarryOrZero, false),
            (X86Condition::A, FlagFormula::CarryOrZero, true),
            (X86Condition::L, FlagFormula::Less, false),
            (X86Condition::Ge, FlagFormula::Less, true),
            (X86Condition::Le, FlagFormula::LessOrEqual, false),
            (X86Condition::G, FlagFormula::LessOrEqual, true),
        ];
        for (condition, formula, negated) in table {
            assert_eq!(
                condition_formula(condition),
                (formula, negated),
                "{condition:?}"
            );
        }
    }

    /// Clearing makes every flag unknown; `BT` keeps only the carry it sets.
    #[test]
    fn clearing_forgets_the_flags() {
        let mut flags = FlagState::new();
        let carry = SsaVarId::from_index(2);
        flags.set_compare(SsaVarId::from_index(0), SsaVarId::from_index(1));
        flags.set_carry(carry);
        assert!(flags.is_known());

        flags.clear();
        assert!(!flags.is_known());
        assert_eq!(flags.carry(), None);

        flags.set_compare(SsaVarId::from_index(0), SsaVarId::from_index(1));
        flags.set_carry_only(carry);
        assert!(!flags.is_known());
        assert_eq!(flags.carry(), Some(carry));
    }

    #[test]
    fn test_condition_classification() {
        assert!(is_zero_flag_only(X86Condition::E));
        assert!(is_zero_flag_only(X86Condition::Ne));
        assert!(!is_zero_flag_only(X86Condition::L));

        assert!(is_signed_condition(X86Condition::L));
        assert!(is_signed_condition(X86Condition::G));
        assert!(!is_signed_condition(X86Condition::B));

        assert!(is_unsigned_condition(X86Condition::B));
        assert!(is_unsigned_condition(X86Condition::A));
        assert!(!is_unsigned_condition(X86Condition::L));
    }
}

#[cfg(test)]
mod examples {
    use super::FlagState;
    use crate::{
        analysis::{CmpKind, SsaVarId, X86Condition},
        Result,
    };

    #[test]
    fn module_example() -> Result<()> {
        let mut flags = FlagState::new();

        // After CMP eax, 10
        let v0 = SsaVarId::from_index(0); // SSA var for eax
        let v1 = SsaVarId::from_index(1); // SSA var for constant 10
        flags.set_compare(v0, v1);

        // Get SSA comparison for JL
        let (cmp, left, right, unsigned) = flags.comparison(X86Condition::L).unwrap();
        assert_eq!(cmp, CmpKind::Lt);
        assert_eq!((left, right), (v0, v1));
        assert!(!unsigned);
        Ok(())
    }
}

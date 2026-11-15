//! Z3-based constraint solver for symbolic expressions.
//!
//! This module provides [`Z3Solver`], which translates [`SymbolicExpr`] trees
//! to Z3's AST and uses Z3's SMT solver to find solutions to constraints.
//! All computations use 32-bit bitvectors matching CIL's `int32` semantics.

use std::collections::HashMap;

use analyssa::{
    analysis::{
        consts::scalar::{ScalarKind, ScalarOperation},
        symbolic::expr::SymbolicExpr as GenericSymbolicExpr,
    },
    ir::{evaluation::NumericOp, integer::IntegerType},
};

use crate::{analysis::ssa::CilTarget, metadata::typesystem::PointerSize};

type SymbolicExpr = GenericSymbolicExpr<CilTarget>;

/// Z3-based constraint solver for symbolic expressions.
///
/// This solver translates our `SymbolicExpr` IR to Z3's AST and uses Z3's
/// SMT solver to find solutions to constraints. The solver is stateless;
/// each solving operation creates a fresh Z3 context internally.
///
/// # Example
///
/// ```rust,no_run
/// use dotscope::analysis::{SymbolicExpr, NumericOp, Z3Solver};
///
/// let solver = Z3Solver::new();
///
/// // Find all state values where (state XOR 0x12345678) % 13 == 5
/// let expr = SymbolicExpr::binary(
///     NumericOp::RemU,
///     SymbolicExpr::binary(
///         NumericOp::Xor,
///         SymbolicExpr::named("state"),
///         SymbolicExpr::constant_i32(0x12345678),
///     ),
///     SymbolicExpr::constant_i32(13),
/// );
///
/// let solutions = solver.solve_for_value(&expr, "state", 5, 100);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Z3Solver;

impl Z3Solver {
    /// Creates a new Z3 solver instance.
    ///
    /// The solver uses Z3's default configuration with 32-bit bitvector logic.
    ///
    /// # Returns
    ///
    /// A new [`Z3Solver`] ready to solve constraints.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Finds values for a named variable that make the expression equal to a target.
    ///
    /// Uses Z3 to enumerate solutions by repeatedly solving and excluding found
    /// solutions until `max_solutions` are found or no more solutions exist.
    ///
    /// # Arguments
    ///
    /// * `expr` - The symbolic expression to solve.
    /// * `var_name` - The name of the variable to solve for (must appear in `expr`).
    /// * `target` - The target value the expression should equal.
    /// * `max_solutions` - Maximum number of solutions to return.
    ///
    /// # Returns
    ///
    /// A vector of values for `var_name` that make `expr == target`.
    /// May contain fewer than `max_solutions` if fewer solutions exist.
    #[must_use]
    pub fn solve_for_value(
        &self,
        expr: &SymbolicExpr,
        var_name: &str,
        target: i64,
        max_solutions: usize,
    ) -> Vec<i64> {
        let solver = z3::Solver::new();

        // Create the variable we're solving for as a 32-bit bitvector
        let var = z3::ast::BV::new_const(var_name, 32);

        // Build variable map
        let mut var_map: HashMap<String, z3::ast::BV> = HashMap::new();
        var_map.insert(var_name.to_string(), var.clone());

        // Translate expression to Z3
        let z3_expr = self.translate_to_z3(expr, &var_map);

        // Add constraint: expr == target
        let target_bv = z3::ast::BV::from_i64(target, 32);
        solver.assert(z3_expr.eq(&target_bv));

        // Enumerate solutions
        let mut solutions = Vec::new();
        while solutions.len() < max_solutions {
            match solver.check() {
                z3::SatResult::Sat => {
                    let Some(model) = solver.get_model() else {
                        break;
                    };
                    let Some(val) = model.eval(&var, true) else {
                        break;
                    };
                    let solution = val.as_i64().unwrap_or(0);
                    solutions.push(solution);

                    // Exclude this solution and continue
                    let exclude = var.eq(z3::ast::BV::from_i64(solution, 32));
                    solver.assert(exclude.not());
                }
                _ => break,
            }
        }

        solutions
    }

    /// Finds values within a range that make the expression equal to a target.
    ///
    /// Similar to [`solve_for_value`](Self::solve_for_value), but adds range
    /// constraints to restrict the search space. More efficient when you know
    /// the valid range of input values.
    ///
    /// # Arguments
    ///
    /// * `expr` - The symbolic expression to solve.
    /// * `var_name` - The name of the variable to solve for.
    /// * `target` - The target value the expression should equal.
    /// * `min_val` - Minimum allowed value for the variable (inclusive).
    /// * `max_val` - Maximum allowed value for the variable (inclusive).
    /// * `max_solutions` - Maximum number of solutions to return.
    ///
    /// # Returns
    ///
    /// A vector of values in `[min_val, max_val]` that make `expr == target`.
    #[must_use]
    pub fn solve_in_range(
        &self,
        expr: &SymbolicExpr,
        var_name: &str,
        target: i64,
        min_val: i64,
        max_val: i64,
        max_solutions: usize,
    ) -> Vec<i64> {
        let solver = z3::Solver::new();

        let var = z3::ast::BV::new_const(var_name, 32);

        let mut var_map: HashMap<String, z3::ast::BV> = HashMap::new();
        var_map.insert(var_name.to_string(), var.clone());

        let z3_expr = self.translate_to_z3(expr, &var_map);

        // Constraint: expr == target
        let target_bv = z3::ast::BV::from_i64(target, 32);
        solver.assert(z3_expr.eq(&target_bv));

        // Range constraints (signed comparison)
        let min_bv = z3::ast::BV::from_i64(min_val, 32);
        let max_bv = z3::ast::BV::from_i64(max_val, 32);
        solver.assert(var.bvsge(&min_bv));
        solver.assert(var.bvsle(&max_bv));

        let mut solutions = Vec::new();
        while solutions.len() < max_solutions {
            match solver.check() {
                z3::SatResult::Sat => {
                    let Some(model) = solver.get_model() else {
                        break;
                    };
                    let Some(val) = model.eval(&var, true) else {
                        break;
                    };
                    let solution = val.as_i64().unwrap_or(0);
                    solutions.push(solution);

                    let exclude = var.eq(z3::ast::BV::from_i64(solution, 32));
                    solver.assert(exclude.not());
                }
                _ => break,
            }
        }

        solutions
    }

    /// Builds a complete mapping from case indices to input values.
    ///
    /// For each possible case index (0 to `num_cases - 1`), finds input values
    /// that produce that case index. This is the primary method for control flow
    /// unflattening, where we need to know which state values reach which switch cases.
    ///
    /// # Arguments
    ///
    /// * `expr` - The switch selector expression (e.g., `(state XOR C) % N`).
    /// * `var_name` - The name of the state variable to solve for.
    /// * `num_cases` - The number of switch cases to map.
    /// * `solutions_per_case` - Maximum solutions to find for each case.
    ///
    /// # Returns
    ///
    /// A map from case index to the list of input values that reach that case.
    /// Cases with no reachable inputs are omitted from the map.
    #[must_use]
    #[allow(clippy::cast_possible_wrap)] // case_idx is small (switch case count) - safe to convert to i64
    pub fn build_case_mapping(
        &self,
        expr: &SymbolicExpr,
        var_name: &str,
        num_cases: usize,
        solutions_per_case: usize,
    ) -> HashMap<usize, Vec<i64>> {
        let mut mapping = HashMap::new();

        for case_idx in 0..num_cases {
            let solutions =
                self.solve_for_value(expr, var_name, case_idx as i64, solutions_per_case);
            if !solutions.is_empty() {
                mapping.insert(case_idx, solutions);
            }
        }

        mapping
    }

    /// Checks if any value exists that makes the expression equal to a target.
    ///
    /// This is faster than [`solve_for_value`](Self::solve_for_value) when you
    /// only need to know if a solution exists, not what the solutions are.
    ///
    /// # Arguments
    ///
    /// * `expr` - The symbolic expression to check.
    /// * `var_name` - The name of the variable in the expression.
    /// * `target` - The target value to check for satisfiability.
    ///
    /// # Returns
    ///
    /// `true` if there exists a value for `var_name` that makes `expr == target`.
    #[must_use]
    pub fn is_satisfiable(&self, expr: &SymbolicExpr, var_name: &str, target: i64) -> bool {
        let solver = z3::Solver::new();

        let var = z3::ast::BV::new_const(var_name, 32);

        let mut var_map: HashMap<String, z3::ast::BV> = HashMap::new();
        var_map.insert(var_name.to_string(), var);

        let z3_expr = self.translate_to_z3(expr, &var_map);
        let target_bv = z3::ast::BV::from_i64(target, 32);
        solver.assert(z3_expr.eq(&target_bv));

        matches!(solver.check(), z3::SatResult::Sat)
    }

    /// Checks if a boolean expression is an opaque predicate.
    ///
    /// An opaque predicate is a condition that always evaluates to the same
    /// boolean value regardless of inputs. Obfuscators use these to add fake
    /// branches that are never/always taken.
    ///
    /// This method checks satisfiability for both outcomes (true and false)
    /// to determine if the predicate is opaque:
    /// - Always true: can be true but never false
    /// - Always false: can be false but never true
    /// - Not opaque: can be both true and false
    ///
    /// # Arguments
    ///
    /// * `expr` - The condition expression to analyze.
    /// * `var_names` - Names of symbolic variables in the expression.
    ///
    /// # Returns
    ///
    /// - `Some(true)` if the predicate is always true
    /// - `Some(false)` if the predicate is always false
    /// - `None` if the predicate is not opaque (can be both true and false)
    #[must_use]
    pub fn check_opaque_predicate(&self, expr: &SymbolicExpr, var_names: &[&str]) -> Option<bool> {
        // Check if the expression can evaluate to true (non-zero)
        let can_be_true = self.is_satisfiable_bool(expr, var_names, true);

        // Check if the expression can evaluate to false (zero)
        let can_be_false = self.is_satisfiable_bool(expr, var_names, false);

        match (can_be_true, can_be_false) {
            (true, false) => Some(true),  // Always true - opaque predicate
            (false, true) => Some(false), // Always false - opaque predicate
            _ => None,                    // Not opaque - can be both
        }
    }

    /// Checks if a boolean expression can evaluate to a specific truth value.
    ///
    /// For boolean expressions (comparisons), we check if the expression can
    /// be non-zero (true) or zero (false).
    ///
    /// # Arguments
    ///
    /// * `expr` - The boolean expression to check.
    /// * `var_names` - Names of symbolic variables in the expression.
    /// * `target_true` - If true, check if expr can be non-zero; if false, check if expr can be zero.
    ///
    /// # Returns
    ///
    /// `true` if the expression can evaluate to the target truth value.
    #[must_use]
    pub fn is_satisfiable_bool(
        &self,
        expr: &SymbolicExpr,
        var_names: &[&str],
        target_true: bool,
    ) -> bool {
        let solver = z3::Solver::new();

        // Create all symbolic variables
        let mut var_map: HashMap<String, z3::ast::BV> = HashMap::new();
        for name in var_names {
            let var = z3::ast::BV::new_const(*name, 32);
            var_map.insert((*name).to_string(), var);
        }

        // Translate expression to Z3
        let z3_expr = self.translate_to_z3(expr, &var_map);

        // For boolean: true means non-zero, false means zero
        let zero = z3::ast::BV::from_i64(0, 32);
        if target_true {
            // Check if expr can be non-zero (true)
            solver.assert(z3_expr.eq(&zero).not());
        } else {
            // Check if expr can be zero (false)
            solver.assert(z3_expr.eq(&zero));
        }

        matches!(solver.check(), z3::SatResult::Sat)
    }

    /// Checks if an expression is constant for all input values.
    ///
    /// This determines if the expression always produces the same value
    /// regardless of the symbolic variable's value. Useful for detecting
    /// expressions that have been simplified to constants by the obfuscator.
    ///
    /// # Arguments
    ///
    /// * `expr` - The expression to check.
    /// * `var_name` - The name of the symbolic variable.
    ///
    /// # Returns
    ///
    /// `Some(value)` if the expression is constant, `None` if it varies.
    #[must_use]
    pub fn is_constant_expression(
        &self,
        expr: &SymbolicExpr,
        var_name: &str,
        ptr_size: PointerSize,
    ) -> Option<i64> {
        // Check if there are at least two different outputs for different inputs
        let solver = z3::Solver::new();

        let var1 = z3::ast::BV::new_const(format!("{var_name}_1"), 32);
        let var2 = z3::ast::BV::new_const(format!("{var_name}_2"), 32);

        let mut var_map1: HashMap<String, z3::ast::BV> = HashMap::new();
        var_map1.insert(var_name.to_string(), var1.clone());

        let mut var_map2: HashMap<String, z3::ast::BV> = HashMap::new();
        var_map2.insert(var_name.to_string(), var2.clone());

        let z3_expr1 = self.translate_to_z3(expr, &var_map1);
        let z3_expr2 = self.translate_to_z3(expr, &var_map2);

        // Assert that the two inputs produce different outputs
        solver.assert(z3_expr1.eq(&z3_expr2).not());

        match solver.check() {
            z3::SatResult::Sat | z3::SatResult::Unknown => None, // Expression can produce different values, or can't determine
            z3::SatResult::Unsat => {
                // Expression is constant - find the value
                // Evaluate with any input (e.g., 0)
                if let Some(c) = expr
                    .substitute_named(var_name, &SymbolicExpr::constant_i64(0))
                    .simplify(ptr_size)
                    .as_i64()
                {
                    Some(c)
                } else {
                    // Try Z3 to find the constant value
                    let solver2 = z3::Solver::new();
                    let var = z3::ast::BV::new_const(var_name, 32);
                    let mut vm: HashMap<String, z3::ast::BV> = HashMap::new();
                    vm.insert(var_name.to_string(), var);
                    let e = self.translate_to_z3(expr, &vm);

                    // Just check satisfiability and get the expression value
                    if let z3::SatResult::Sat = solver2.check() {
                        if let Some(model) = solver2.get_model() {
                            if let Some(val) = model.eval(&e, true) {
                                return val.as_i64();
                            }
                        }
                    }
                    None
                }
            }
        }
    }

    /// Translates a symbolic expression to Z3's bitvector AST.
    ///
    /// Recursively converts our [`SymbolicExpr`] IR to Z3's internal representation.
    /// All values are represented as 32-bit bitvectors to match CIL semantics.
    ///
    /// # Arguments
    ///
    /// * `expr` - The symbolic expression to translate.
    /// * `var_map` - Map from variable names to their Z3 bitvector representations.
    ///
    /// # Returns
    ///
    /// The Z3 bitvector AST representing the expression.
    #[allow(
        clippy::self_only_used_in_recursion,
        clippy::trivially_copy_pass_by_ref
    )] // Recursive helper method - &self maintains method organization
    fn translate_to_z3(
        &self,
        expr: &SymbolicExpr,
        var_map: &HashMap<String, z3::ast::BV>,
    ) -> z3::ast::BV {
        match expr {
            // An integer is its low word; a constant without integer bits
            // (a float, a string) is a value of its own, unconstrained.
            SymbolicExpr::Constant(v) => match (v.as_i64(), v.as_u64()) {
                (Some(signed), _) => z3::ast::BV::from_i64(signed, 32),
                (None, Some(unsigned)) => z3::ast::BV::from_u64(unsigned, 32),
                (None, None) => z3::ast::BV::fresh_const("constant", 32),
            },

            SymbolicExpr::Variable(var_id) => {
                // Create a unique name for SSA variables
                let name = format!("ssa_{}", var_id.index());
                z3::ast::BV::new_const(name, 32)
            }

            // One execution of a definition is an unconstrained value of its
            // own: neither the SSA variable nor another execution of it.
            SymbolicExpr::Instance(instance) => {
                let name = format!(
                    "instance_{}_{}",
                    instance.source().index(),
                    instance.generation()
                );
                z3::ast::BV::new_const(name, 32)
            }

            SymbolicExpr::NamedVar(name) => {
                if let Some(var) = var_map.get(name) {
                    var.clone()
                } else {
                    // Create new variable if not in map
                    z3::ast::BV::new_const(name.as_str(), 32)
                }
            }

            SymbolicExpr::Unary { op, operand } => {
                Self::numeric_unary(*op, self.translate_to_z3(operand, var_map))
            }

            SymbolicExpr::Binary { op, left, right } => Self::numeric_binary(
                *op,
                &self.translate_to_z3(left, var_map),
                &self.translate_to_z3(right, var_map),
            ),

            SymbolicExpr::TypedUnary { op, operand } => {
                Self::scalar_unary(**op, self.translate_to_z3(operand, var_map))
            }

            SymbolicExpr::TypedBinary { op, left, right } => Self::scalar_binary(
                **op,
                &self.translate_to_z3(left, var_map),
                &self.translate_to_z3(right, var_map),
            ),
        }
    }

    /// Translates a unary numeric operation over the 32-bit word `operand`.
    ///
    /// A bit scan of zero has no index, so its result there is a value of
    /// its own, unconstrained. A binary operation has no meaning over one
    /// operand and is unconstrained as well.
    fn numeric_unary(op: NumericOp, operand: z3::ast::BV) -> z3::ast::BV {
        let bit = |index: u32| operand.extract(index, index);
        let set = |index: u32| bit(index).eq(z3::ast::BV::from_u64(1, 1));
        match op {
            NumericOp::Neg => operand.bvneg(),
            NumericOp::Not => operand.bvnot(),
            NumericOp::BSwap => (8..32)
                .step_by(8)
                .fold(operand.extract(7, 0), |swapped, low| {
                    swapped.concat(operand.extract(low | 7, low))
                }),
            NumericOp::BRev => (1..32).fold(bit(0), |reversed, index| reversed.concat(bit(index))),
            NumericOp::BitScanForward => (0..32)
                .rev()
                .fold(z3::ast::BV::fresh_const("bsf_zero", 32), |higher, index| {
                    set(index).ite(&z3::ast::BV::from_u64(index.into(), 32), &higher)
                }),
            NumericOp::BitScanReverse => (0..32)
                .fold(z3::ast::BV::fresh_const("bsr_zero", 32), |lower, index| {
                    set(index).ite(&z3::ast::BV::from_u64(index.into(), 32), &lower)
                }),
            NumericOp::Popcount => Self::population(&operand),
            NumericOp::Parity => Self::population(&operand).bvand(z3::ast::BV::from_u64(1, 32)),
            NumericOp::Add
            | NumericOp::Sub
            | NumericOp::Mul
            | NumericOp::DivS
            | NumericOp::DivU
            | NumericOp::RemS
            | NumericOp::RemU
            | NumericOp::Rol
            | NumericOp::Ror
            | NumericOp::And
            | NumericOp::Or
            | NumericOp::Xor
            | NumericOp::Shl
            | NumericOp::ShrS
            | NumericOp::ShrU
            | NumericOp::Eq
            | NumericOp::Ne
            | NumericOp::LtS
            | NumericOp::LtU
            | NumericOp::GtS
            | NumericOp::GtU
            | NumericOp::LeS
            | NumericOp::LeU
            | NumericOp::GeS
            | NumericOp::GeU => z3::ast::BV::fresh_const("malformed", 32),
        }
    }

    /// The number of set bits of the 32-bit word `operand`.
    fn population(operand: &z3::ast::BV) -> z3::ast::BV {
        (0..32).fold(z3::ast::BV::from_u64(0, 32), |count, index| {
            count.bvadd(operand.extract(index, index).zero_ext(31))
        })
    }

    /// Translates a binary numeric operation over `left` and `right`.
    fn numeric_binary(op: NumericOp, left: &z3::ast::BV, right: &z3::ast::BV) -> z3::ast::BV {
        match op {
            NumericOp::Add => left.bvadd(right),
            NumericOp::Sub => left.bvsub(right),
            NumericOp::Mul => left.bvmul(right),
            NumericOp::DivS => left.bvsdiv(right),
            NumericOp::DivU => left.bvudiv(right),
            NumericOp::RemS => left.bvsrem(right),
            NumericOp::RemU => left.bvurem(right),
            NumericOp::And => left.bvand(right),
            NumericOp::Or => left.bvor(right),
            NumericOp::Xor => left.bvxor(right),
            NumericOp::Shl => Self::shifted(right, left.bvshl(right)),
            NumericOp::ShrS => Self::shifted(right, left.bvashr(right)),
            NumericOp::ShrU => Self::shifted(right, left.bvlshr(right)),
            // Comparisons return 1 or 0
            NumericOp::Eq => left
                .eq(right)
                .ite(&z3::ast::BV::from_i64(1, 32), &z3::ast::BV::from_i64(0, 32)),
            NumericOp::Ne => left
                .eq(right)
                .not()
                .ite(&z3::ast::BV::from_i64(1, 32), &z3::ast::BV::from_i64(0, 32)),
            NumericOp::LtS => left
                .bvslt(right)
                .ite(&z3::ast::BV::from_i64(1, 32), &z3::ast::BV::from_i64(0, 32)),
            NumericOp::LtU => left
                .bvult(right)
                .ite(&z3::ast::BV::from_i64(1, 32), &z3::ast::BV::from_i64(0, 32)),
            NumericOp::GtS => left
                .bvsgt(right)
                .ite(&z3::ast::BV::from_i64(1, 32), &z3::ast::BV::from_i64(0, 32)),
            NumericOp::GtU => left
                .bvugt(right)
                .ite(&z3::ast::BV::from_i64(1, 32), &z3::ast::BV::from_i64(0, 32)),
            NumericOp::LeS => left
                .bvsle(right)
                .ite(&z3::ast::BV::from_i64(1, 32), &z3::ast::BV::from_i64(0, 32)),
            NumericOp::LeU => left
                .bvule(right)
                .ite(&z3::ast::BV::from_i64(1, 32), &z3::ast::BV::from_i64(0, 32)),
            NumericOp::GeS => left
                .bvsge(right)
                .ite(&z3::ast::BV::from_i64(1, 32), &z3::ast::BV::from_i64(0, 32)),
            NumericOp::GeU => left
                .bvuge(right)
                .ite(&z3::ast::BV::from_i64(1, 32), &z3::ast::BV::from_i64(0, 32)),
            // Rotate operations.
            NumericOp::Rol => left.bvrotl(right),
            NumericOp::Ror => left.bvrotr(right),
            // A unary operation has no meaning over two operands.
            NumericOp::Neg
            | NumericOp::Not
            | NumericOp::BSwap
            | NumericOp::BRev
            | NumericOp::BitScanForward
            | NumericOp::BitScanReverse
            | NumericOp::Popcount
            | NumericOp::Parity => z3::ast::BV::fresh_const("malformed", 32),
        }
    }

    /// The word a shift by `amount` yields, `shifted` for a distance inside
    /// the word: a distance of the word's width or more shifts by each
    /// target's own convention, so its result is a value of its own,
    /// unconstrained.
    fn shifted(amount: &z3::ast::BV, shifted: z3::ast::BV) -> z3::ast::BV {
        amount
            .bvult(z3::ast::BV::from_u64(32, 32))
            .ite(&shifted, &z3::ast::BV::fresh_const("shifted_out", 32))
    }

    /// Translates a unary operation that keeps its declared scalar semantics.
    ///
    /// A checked operation's value, where it returns, is the wrapping one; an
    /// overflow traps and yields none. A copy is its operand, and a conversion
    /// the operand as its target holds it ([`Self::converted`]).
    fn scalar_unary(op: ScalarOperation, operand: z3::ast::BV) -> z3::ast::BV {
        match op.kind() {
            ScalarKind::Numeric(numeric) | ScalarKind::Checked { op: numeric, .. } => {
                Self::numeric_unary(numeric, operand)
            }
            ScalarKind::Convert { target, .. } => Self::converted(&operand, target),
            ScalarKind::Copy => operand,
        }
    }

    /// Translates a binary operation that keeps its declared scalar semantics,
    /// a checked one as the wrapping value it returns with. A conversion and
    /// a copy take one operand, so over two they are unconstrained.
    fn scalar_binary(op: ScalarOperation, left: &z3::ast::BV, right: &z3::ast::BV) -> z3::ast::BV {
        match op.kind() {
            ScalarKind::Numeric(numeric) | ScalarKind::Checked { op: numeric, .. } => {
                Self::numeric_binary(numeric, left, right)
            }
            ScalarKind::Convert { .. } | ScalarKind::Copy => {
                z3::ast::BV::fresh_const("malformed", 32)
            }
        }
    }

    /// The 32-bit value `operand` is as `target` holds it: its low bits,
    /// extended by the target's sign, where the target is narrower than the
    /// model's word, and the word itself otherwise. A checked conversion
    /// that returns holds a value in range, which is the same bits.
    fn converted(operand: &z3::ast::BV, target: IntegerType) -> z3::ast::BV {
        let bits = target.bits();
        if bits >= 32 {
            return operand.clone();
        }
        let low = operand.extract(bits.saturating_sub(1), 0);
        if target.signed() {
            low.sign_ext(32u32.saturating_sub(bits))
        } else {
            low.zero_ext(32u32.saturating_sub(bits))
        }
    }
}

#[cfg(test)]
mod tests {
    use analyssa::{
        analysis::{consts::scalar::ScalarOperation, symbolic::expr::SymbolicExpr},
        ir::evaluation::NumericOp,
    };

    use crate::{
        analysis::{
            ssa::symbolic::Z3Solver, CilTarget, ConstValue, SsaEvaluator, SsaFunctionBuilder,
            SsaType,
        },
        metadata::typesystem::PointerSize,
    };

    /// An operation that keeps its declared scalar semantics solves as that
    /// operation: `conv.i1` holds a byte's range sign-extended, `conv.u1` the
    /// same byte zero-extended, and a checked add, where it returns, the sum.
    /// The control: the word a byte's conversion cannot reach is no solution.
    #[test]
    fn test_z3_typed_operation_solves_as_its_declared_semantics() {
        let mut defined = Vec::new();
        let ssa = SsaFunctionBuilder::new(1, 0)
            .build_with(|f| {
                let input = f.arg(0, SsaType::I32);
                f.block(0, |b| {
                    defined.push(b.conv(input, SsaType::I8));
                    defined.push(b.conv(input, SsaType::U8));
                    defined.push(b.add_ovf(input, input));
                    b.ret();
                });
            })
            .unwrap();
        let machine = CilTarget::x86().machine();
        let operation = |value| {
            let op = ssa.get_definition(value).unwrap();
            ScalarOperation::capture(&ssa, op, machine).unwrap().0
        };
        let x = || SymbolicExpr::named("x");
        let signed = SymbolicExpr::typed_unary(operation(defined[0]), x()).unwrap();
        let unsigned = SymbolicExpr::typed_unary(operation(defined[1]), x()).unwrap();
        let sum = SymbolicExpr::typed_binary(operation(defined[2]), x(), x()).unwrap();

        let solver = Z3Solver::new();
        assert!(solver.is_satisfiable(&signed, "x", -128));
        assert!(
            !solver.is_satisfiable(&signed, "x", 0x80),
            "a signed byte is never 128"
        );
        assert!(solver.is_satisfiable(&unsigned, "x", 0x80));
        assert!(
            !solver.is_satisfiable(&unsigned, "x", -1),
            "an unsigned byte is never all ones"
        );
        assert!(solver.is_satisfiable(&sum, "x", 10));
        assert!(!solver.is_satisfiable(&sum, "x", 7), "twice a word is even");
    }

    /// Every operation solves as the value it computes, and one whose value
    /// the program leaves to the target solves as no value in particular.
    /// The bit operations over 0x112 (bits 1, 4 and 8) state their results;
    /// a bit scan of zero, a shift by the word's width, a constant without
    /// integer bits and an operation given the wrong number of operands
    /// prove nothing; an unsigned 64-bit constant is its low word.
    #[test]
    fn test_z3_operations_solve_as_the_values_they_compute() {
        let solver = Z3Solver::new();
        let always = |expr: SymbolicExpr<CilTarget>, expected: i64| {
            let predicate =
                SymbolicExpr::binary(NumericOp::Eq, expr, SymbolicExpr::constant_i64(expected));
            solver.check_opaque_predicate(&predicate, &[])
        };
        let bits = || SymbolicExpr::constant_i32(0x112);
        for (op, expected) in [
            (NumericOp::BSwap, 0x1201_0000),
            (NumericOp::BRev, 0x4880_0000),
            (NumericOp::Popcount, 3),
            (NumericOp::Parity, 1),
            (NumericOp::BitScanForward, 1),
            (NumericOp::BitScanReverse, 8),
        ] {
            assert_eq!(
                always(SymbolicExpr::unary(op, bits()), expected),
                Some(true),
                "{op:?}"
            );
        }
        for op in [NumericOp::BitScanForward, NumericOp::BitScanReverse] {
            let zero = SymbolicExpr::unary(op, SymbolicExpr::constant_i32(0));
            assert_eq!(always(zero, 0), None, "{op:?} of zero");
        }
        let one = || SymbolicExpr::constant_i32(1);
        let shifted = |distance| {
            SymbolicExpr::binary(NumericOp::Shl, one(), SymbolicExpr::constant_i32(distance))
        };
        assert_eq!(always(shifted(31), i64::from(i32::MIN)), Some(true));
        assert_eq!(always(shifted(32), 0), None, "shifted by the width");
        let string = SymbolicExpr::constant(ConstValue::String(0));
        assert_eq!(always(string, 0), None, "a string's token");
        let wide = SymbolicExpr::constant(ConstValue::U64(0xFFFF_FFFF_0000_0005));
        assert_eq!(always(wide, 5), Some(true), "the low word");
        let unary_as_binary = SymbolicExpr::binary(NumericOp::Popcount, bits(), bits());
        assert_eq!(always(unary_as_binary, 0x112), None);
        let binary_as_unary = SymbolicExpr::unary(NumericOp::Add, bits());
        assert_eq!(always(binary_as_unary, 0x112), None);
    }

    /// One execution of an opaque definition is its own unconstrained value:
    /// equal to itself, but not tied to the SSA variable it came from. A tree
    /// past the evaluator's size limit is such an execution.
    #[test]
    fn test_z3_instance_is_distinct_from_its_variable() {
        let mut defined = None;
        let ssa = SsaFunctionBuilder::new(1, 0)
            .build_with(|f| {
                let input = f.arg(0, SsaType::I32);
                f.block(0, |b| {
                    let mut value = input;
                    for _ in 0..13 {
                        value = b.mul(value, value);
                    }
                    defined = Some(value);
                    b.ret();
                });
            })
            .unwrap();
        let squared = defined.unwrap();
        let mut eval = SsaEvaluator::new(&ssa, CilTarget::x86().machine());
        eval.set_symbolic(ssa.argument_variables().next().unwrap().id(), "x");
        eval.evaluate_block(0);
        let read = eval.get(squared).cloned().unwrap();
        let mut found = None;
        read.for_each_instance(|instance| {
            found.get_or_insert(instance);
        });
        let instance = found.unwrap_or_else(|| panic!("{read:?}"));
        let opaque = SymbolicExpr::Instance(instance);

        let solver = Z3Solver::new();
        let itself = SymbolicExpr::binary(NumericOp::Eq, opaque.clone(), opaque.clone());
        assert_eq!(solver.check_opaque_predicate(&itself, &[]), Some(true));
        let variable = SymbolicExpr::binary(
            NumericOp::Eq,
            opaque,
            SymbolicExpr::Variable(instance.source()),
        );
        assert_eq!(solver.check_opaque_predicate(&variable, &[]), None);
    }

    #[test]
    fn test_z3_simple_solve() {
        let solver = Z3Solver::new();

        // Solve: state + 5 = 10  =>  state = 5
        let expr = SymbolicExpr::binary(
            NumericOp::Add,
            SymbolicExpr::named("state"),
            SymbolicExpr::constant_i32(5),
        );

        let solutions = solver.solve_for_value(&expr, "state", 10, 10);
        assert!(!solutions.is_empty());
        assert!(solutions.contains(&5));
    }

    #[test]
    fn test_z3_xor_solve() {
        let solver = Z3Solver::new();

        // Solve: state XOR 0x1234 = 0x5678
        let expr = SymbolicExpr::binary(
            NumericOp::Xor,
            SymbolicExpr::named("state"),
            SymbolicExpr::constant_i32(0x1234),
        );

        let solutions = solver.solve_for_value(&expr, "state", 0x5678, 10);
        assert!(!solutions.is_empty());

        // Verify: state XOR 0x1234 should equal 0x5678
        let state = solutions[0];
        assert_eq!((state as i32) ^ 0x1234, 0x5678);
    }

    #[test]
    fn test_z3_xor_modulo_solve() {
        let solver = Z3Solver::new();

        // Solve: (state XOR 0x12345678) % 13 = 5
        let xored = SymbolicExpr::binary(
            NumericOp::Xor,
            SymbolicExpr::named("state"),
            SymbolicExpr::constant_i32(0x12345678),
        );
        let expr = SymbolicExpr::binary(NumericOp::RemU, xored, SymbolicExpr::constant_i32(13));

        let solutions = solver.solve_for_value(&expr, "state", 5, 10);
        assert!(!solutions.is_empty());

        // Verify all solutions
        for &sol in &solutions {
            let xor_result = (sol as u32) ^ 0x12345678u32;
            assert_eq!(xor_result % 13, 5);
        }
    }

    #[test]
    fn test_z3_build_case_mapping() {
        let solver = Z3Solver::new();

        // Build mapping for: state % 5
        let expr = SymbolicExpr::binary(
            NumericOp::RemU,
            SymbolicExpr::named("state"),
            SymbolicExpr::constant_i32(5),
        );

        let mapping = solver.build_case_mapping(&expr, "state", 5, 3);

        // Should have solutions for cases 0-4
        assert_eq!(mapping.len(), 5);
        for case_idx in 0..5 {
            assert!(mapping.contains_key(&case_idx));
        }
    }

    #[test]
    fn test_z3_is_satisfiable() {
        let solver = Z3Solver::new();

        // state % 5 = 3 should be satisfiable
        let expr = SymbolicExpr::binary(
            NumericOp::RemU,
            SymbolicExpr::named("state"),
            SymbolicExpr::constant_i32(5),
        );
        assert!(solver.is_satisfiable(&expr, "state", 3));

        // state % 5 = 7 should NOT be satisfiable (7 > 5)
        assert!(!solver.is_satisfiable(&expr, "state", 7));
    }

    #[test]
    fn test_opaque_predicate_always_true() {
        let solver = Z3Solver::new();

        // x * x >= 0 is always true for signed 32-bit (squared values are non-negative)
        // Actually this is false due to overflow. Let's use a simpler case:
        // (x | ~x) == -1 is always true (all bits set)
        let x = SymbolicExpr::named("x");
        let not_x = SymbolicExpr::unary(NumericOp::Not, x.clone());
        let or_expr = SymbolicExpr::binary(NumericOp::Or, x, not_x);
        let cmp = SymbolicExpr::binary(NumericOp::Eq, or_expr, SymbolicExpr::constant_i32(-1));

        let result = solver.check_opaque_predicate(&cmp, &["x"]);
        assert_eq!(result, Some(true), "(x | ~x) == -1 should always be true");
    }

    #[test]
    fn test_opaque_predicate_always_false() {
        let solver = Z3Solver::new();

        // (x & ~x) != 0 is always false (x & ~x is always 0)
        let x = SymbolicExpr::named("x");
        let not_x = SymbolicExpr::unary(NumericOp::Not, x.clone());
        let and_expr = SymbolicExpr::binary(NumericOp::And, x, not_x);
        let cmp = SymbolicExpr::binary(NumericOp::Ne, and_expr, SymbolicExpr::constant_i32(0));

        let result = solver.check_opaque_predicate(&cmp, &["x"]);
        assert_eq!(result, Some(false), "(x & ~x) != 0 should always be false");
    }

    #[test]
    fn test_opaque_predicate_not_opaque() {
        let solver = Z3Solver::new();

        // x > 0 is NOT an opaque predicate (can be true or false)
        let expr = SymbolicExpr::binary(
            NumericOp::GtS,
            SymbolicExpr::named("x"),
            SymbolicExpr::constant_i32(0),
        );

        let result = solver.check_opaque_predicate(&expr, &["x"]);
        assert_eq!(result, None, "x > 0 should not be opaque");
    }

    #[test]
    fn test_opaque_predicate_complex_always_true() {
        let solver = Z3Solver::new();

        // (x - x) == 0 is always true
        let x = SymbolicExpr::named("x");
        let sub = SymbolicExpr::binary(NumericOp::Sub, x.clone(), x);
        let cmp = SymbolicExpr::binary(NumericOp::Eq, sub, SymbolicExpr::constant_i32(0));

        let result = solver.check_opaque_predicate(&cmp, &["x"]);
        assert_eq!(result, Some(true), "(x - x) == 0 should always be true");
    }

    #[test]
    fn test_opaque_predicate_xor_self() {
        let solver = Z3Solver::new();

        // (x ^ x) == 0 is always true
        let x = SymbolicExpr::named("x");
        let xor = SymbolicExpr::binary(NumericOp::Xor, x.clone(), x);
        let cmp = SymbolicExpr::binary(NumericOp::Eq, xor, SymbolicExpr::constant_i32(0));

        let result = solver.check_opaque_predicate(&cmp, &["x"]);
        assert_eq!(result, Some(true), "(x ^ x) == 0 should always be true");
    }

    #[test]
    fn test_opaque_predicate_multiple_variables() {
        let solver = Z3Solver::new();

        // (x + y) - (y + x) == 0 is always true (commutativity of addition)
        let x = SymbolicExpr::named("x");
        let y = SymbolicExpr::named("y");
        let sum1 = SymbolicExpr::binary(NumericOp::Add, x.clone(), y.clone());
        let sum2 = SymbolicExpr::binary(NumericOp::Add, y, x);
        let diff = SymbolicExpr::binary(NumericOp::Sub, sum1, sum2);
        let cmp = SymbolicExpr::binary(NumericOp::Eq, diff, SymbolicExpr::constant_i32(0));

        let result = solver.check_opaque_predicate(&cmp, &["x", "y"]);
        assert_eq!(
            result,
            Some(true),
            "(x + y) - (y + x) == 0 should always be true"
        );
    }

    #[test]
    fn test_is_satisfiable_bool_true() {
        let solver = Z3Solver::new();

        // x > 5 can be true (e.g., x = 10)
        let expr = SymbolicExpr::binary(
            NumericOp::GtS,
            SymbolicExpr::named("x"),
            SymbolicExpr::constant_i32(5),
        );

        assert!(solver.is_satisfiable_bool(&expr, &["x"], true));
    }

    #[test]
    fn test_is_satisfiable_bool_false() {
        let solver = Z3Solver::new();

        // x > 5 can be false (e.g., x = 0)
        let expr = SymbolicExpr::binary(
            NumericOp::GtS,
            SymbolicExpr::named("x"),
            SymbolicExpr::constant_i32(5),
        );

        assert!(solver.is_satisfiable_bool(&expr, &["x"], false));
    }

    #[test]
    fn test_is_constant_expression_constant() {
        let solver = Z3Solver::new();

        // 5 + 3 is always 8
        let expr = SymbolicExpr::binary(
            NumericOp::Add,
            SymbolicExpr::constant_i32(5),
            SymbolicExpr::constant_i32(3),
        );

        let result = solver.is_constant_expression(&expr, "x", PointerSize::Bit64);
        assert_eq!(result, Some(8), "5 + 3 should be constant 8");
    }

    #[test]
    fn test_is_constant_expression_not_constant() {
        let solver = Z3Solver::new();

        // x + 3 varies with x
        let expr = SymbolicExpr::binary(
            NumericOp::Add,
            SymbolicExpr::named("x"),
            SymbolicExpr::constant_i32(3),
        );

        let result = solver.is_constant_expression(&expr, "x", PointerSize::Bit64);
        assert_eq!(result, None, "x + 3 should not be constant");
    }
}

//! CIL evaluation stack implementation.
//!
//! This module provides [`EvaluationStack`], the primary working area for CIL
//! bytecode execution. The evaluation stack is a last-in-first-out (LIFO) stack
//! where most CIL instructions pop operands and push results.
//!
//! # CIL Stack Semantics
//!
//! The evaluation stack follows these rules:
//! - Each method invocation starts with an empty stack
//! - Instructions pop operands and push results according to their specification
//! - At method return, the stack must contain exactly the return value (or be empty for void)
//! - At control flow merge points, stack depth and types must match
//!
//! # Overflow Protection
//!
//! The stack has a configurable maximum depth to prevent runaway execution from
//! consuming excessive memory. Exceeding this limit returns [`EmulationError::StackOverflow`].
//!
//! # Type-Checked Operations
//!
//! While [`push`](EvaluationStack::push) accepts any [`EmValue`],
//! type-checked pop methods like [`pop_i32`](EvaluationStack::pop_i32) ensure
//! type safety at runtime.

use std::fmt;

use crate::{
    emulation::{engine::EmulationError, EmValue},
    metadata::typesystem::CilFlavor,
    Result,
};

/// CIL evaluation stack with overflow protection.
///
/// The evaluation stack is the primary working area for CIL instructions.
/// Values are pushed and popped according to instruction semantics.
///
/// # Stack Depth Limits
///
/// The stack has a configurable maximum depth to prevent runaway execution.
/// Exceeding this limit returns an error.
///
/// # Type Safety
///
/// While the stack accepts any [`EmValue`], type-checked operations like
/// [`pop_i32`](Self::pop_i32) can ensure type safety at pop time.
///
/// # Example
///
/// ```rust
/// use dotscope::emulation::{EmValue, EvaluationStack};
///
/// let mut stack = EvaluationStack::new(100);
///
/// // Push values
/// stack.push(EmValue::I32(42)).unwrap();
/// stack.push(EmValue::I64(100)).unwrap();
///
/// // Pop values
/// let val = stack.pop().unwrap();
/// assert_eq!(val, EmValue::I64(100));
/// ```
#[derive(Clone, Debug)]
pub struct EvaluationStack {
    /// The stack storage.
    values: Vec<EmValue>,

    /// Maximum allowed stack depth.
    max_depth: usize,
}

impl EvaluationStack {
    /// Creates a new evaluation stack with the given maximum depth.
    ///
    /// # Arguments
    ///
    /// * `max_depth` - Maximum number of values allowed on the stack
    ///
    /// # Example
    ///
    /// ```rust
    /// use dotscope::emulation::EvaluationStack;
    ///
    /// let stack = EvaluationStack::new(1000);
    /// assert!(stack.is_empty());
    /// ```
    #[must_use]
    pub fn new(max_depth: usize) -> Self {
        EvaluationStack {
            values: Vec::with_capacity(max_depth.min(256)),
            max_depth,
        }
    }

    /// Creates a new evaluation stack with default maximum depth (10000).
    #[must_use]
    pub fn default_depth() -> Self {
        Self::new(10000)
    }

    /// Pushes a value onto the stack.
    ///
    /// # Arguments
    ///
    /// * `value` - The value to push
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::StackOverflow`] if the stack is full.
    ///
    /// # Example
    ///
    /// ```rust
    /// use dotscope::emulation::{EmValue, EvaluationStack};
    ///
    /// let mut stack = EvaluationStack::new(2);
    /// stack.push(EmValue::I32(1)).unwrap();
    /// stack.push(EmValue::I32(2)).unwrap();
    /// assert!(stack.push(EmValue::I32(3)).is_err()); // Overflow
    /// ```
    pub fn push(&mut self, value: EmValue) -> Result<()> {
        if self.values.len() >= self.max_depth {
            return Err(EmulationError::StackOverflow.into());
        }
        self.values.push(value);
        Ok(())
    }

    /// Pops a value from the stack.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::StackUnderflow`] if the stack is empty.
    ///
    /// # Example
    ///
    /// ```rust
    /// use dotscope::emulation::{EmValue, EvaluationStack};
    ///
    /// let mut stack = EvaluationStack::new(100);
    /// stack.push(EmValue::I32(42)).unwrap();
    /// let val = stack.pop().unwrap();
    /// assert_eq!(val, EmValue::I32(42));
    /// ```
    pub fn pop(&mut self) -> Result<EmValue> {
        self.values
            .pop()
            .ok_or(EmulationError::StackUnderflow.into())
    }

    /// Peeks at the top value without removing it.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::StackUnderflow`] if the stack is empty.
    pub fn peek(&self) -> Result<&EmValue> {
        self.values
            .last()
            .ok_or(EmulationError::StackUnderflow.into())
    }

    /// Peeks at the value at the given depth from the top.
    ///
    /// Depth 0 is the top of the stack.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::StackUnderflow`] if the depth exceeds stack size.
    pub fn peek_at(&self, depth: usize) -> Result<&EmValue> {
        if depth >= self.values.len() {
            return Err(EmulationError::StackUnderflow.into());
        }
        let idx = self
            .values
            .len()
            .checked_sub(1)
            .and_then(|n| n.checked_sub(depth))
            .ok_or(EmulationError::StackUnderflow)?;
        self.values
            .get(idx)
            .ok_or_else(|| EmulationError::StackUnderflow.into())
    }

    /// Pops a value and verifies it has the expected CIL flavor.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::StackTypeMismatch`] if the type doesn't match.
    pub fn pop_typed(&mut self, expected: &CilFlavor) -> Result<EmValue> {
        let value = self.pop()?;
        let actual = value.cil_flavor();
        if !actual.is_compatible_with(expected) {
            // Put it back before returning error
            self.values.push(value);
            return Err(EmulationError::StackTypeMismatch {
                expected: expected.as_str(),
                found: actual.as_str(),
            }
            .into());
        }
        Ok(value)
    }

    /// Pops an I32 value from the stack.
    ///
    /// # Errors
    ///
    /// Returns error if stack is empty or top value is not I32.
    pub fn pop_i32(&mut self) -> Result<i32> {
        let value = self.pop()?;
        match value {
            EmValue::I32(v) => Ok(v),
            EmValue::Bool(v) => Ok(i32::from(v)),
            EmValue::Char(v) => Ok(v as i32),
            _ => {
                let found = value.cil_flavor();
                self.values.push(value);
                Err(EmulationError::StackTypeMismatch {
                    expected: "int32",
                    found: found.as_str(),
                }
                .into())
            }
        }
    }

    /// Pops an I64 value from the stack.
    ///
    /// # Errors
    ///
    /// Returns error if stack is empty or top value is not I64.
    pub fn pop_i64(&mut self) -> Result<i64> {
        let value = self.pop()?;
        if let EmValue::I64(v) = value {
            Ok(v)
        } else {
            let found = value.cil_flavor();
            self.values.push(value);
            Err(EmulationError::StackTypeMismatch {
                expected: "int64",
                found: found.as_str(),
            }
            .into())
        }
    }

    /// Pops an F32 value from the stack.
    ///
    /// # Errors
    ///
    /// Returns error if stack is empty or top value is not F32.
    pub fn pop_f32(&mut self) -> Result<f32> {
        let value = self.pop()?;
        if let EmValue::F32(v) = value {
            Ok(v)
        } else {
            let found = value.cil_flavor();
            self.values.push(value);
            Err(EmulationError::StackTypeMismatch {
                expected: "float32",
                found: found.as_str(),
            }
            .into())
        }
    }

    /// Pops an F64 value from the stack.
    ///
    /// # Errors
    ///
    /// Returns error if stack is empty or top value is not F64.
    pub fn pop_f64(&mut self) -> Result<f64> {
        let value = self.pop()?;
        match value {
            EmValue::F64(v) => Ok(v),
            EmValue::F32(v) => Ok(f64::from(v)), // F32 can widen to F64
            _ => {
                let found = value.cil_flavor();
                self.values.push(value);
                Err(EmulationError::StackTypeMismatch {
                    expected: "float64",
                    found: found.as_str(),
                }
                .into())
            }
        }
    }

    /// Pops an object reference from the stack (including null).
    ///
    /// # Errors
    ///
    /// Returns error if stack is empty or top value is not an object reference.
    pub fn pop_object_ref(&mut self) -> Result<EmValue> {
        let value = self.pop()?;
        match value {
            EmValue::ObjectRef(_) | EmValue::Null => Ok(value),
            _ => {
                let found = value.cil_flavor();
                self.values.push(value);
                Err(EmulationError::StackTypeMismatch {
                    expected: "object ref",
                    found: found.as_str(),
                }
                .into())
            }
        }
    }

    /// Pops two values for a binary operation.
    ///
    /// Returns (left, right) where right was on top of stack.
    ///
    /// # Errors
    ///
    /// Returns error if stack has fewer than 2 values.
    pub fn pop_binary(&mut self) -> Result<(EmValue, EmValue)> {
        let right = self.pop()?;
        let left = self.pop().inspect_err(|_| {
            // Put right back if left fails
            self.values.push(right.clone());
        })?;
        Ok((left, right))
    }

    /// Duplicates the top value on the stack.
    ///
    /// Implements the CIL `dup` instruction.
    ///
    /// # Errors
    ///
    /// Returns error if stack is empty or would overflow.
    pub fn dup(&mut self) -> Result<()> {
        let value = self.peek()?.clone();
        self.push(value)
    }

    /// Swaps the top two values on the stack.
    ///
    /// # Errors
    ///
    /// Returns error if stack has fewer than 2 values.
    pub fn swap(&mut self) -> Result<()> {
        let len = self.values.len();
        if len < 2 {
            return Err(EmulationError::StackUnderflow.into());
        }
        let top = len.saturating_sub(1);
        let next = len.saturating_sub(2);
        self.values.swap(top, next);
        Ok(())
    }

    /// Clears all values from the stack.
    pub fn clear(&mut self) {
        self.values.clear();
    }

    /// Returns the current depth of the stack.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.values.len()
    }

    /// Returns the maximum depth of the stack.
    #[must_use]
    pub fn max_depth(&self) -> usize {
        self.max_depth
    }

    /// Returns `true` if the stack is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Returns a reference to the underlying values (bottom to top).
    #[must_use]
    pub fn values(&self) -> &[EmValue] {
        &self.values
    }

    /// Returns an iterator over stack values from bottom to top.
    pub fn iter(&self) -> impl Iterator<Item = &EmValue> {
        self.values.iter()
    }

    /// Returns an iterator over stack values from top to bottom.
    pub fn iter_top_down(&self) -> impl Iterator<Item = &EmValue> {
        self.values.iter().rev()
    }

    /// Creates a snapshot of the current stack state.
    ///
    /// Useful for backtracking in analysis.
    #[must_use]
    pub fn snapshot(&self) -> Vec<EmValue> {
        self.values.clone()
    }

    /// Restores the stack to a previous snapshot.
    ///
    /// # Arguments
    ///
    /// * `snapshot` - Previously captured stack state
    pub fn restore(&mut self, snapshot: Vec<EmValue>) {
        self.values = snapshot;
    }

    /// Checks if the stack types match expectations.
    ///
    /// Useful for verifying stack state at merge points.
    ///
    /// # Errors
    ///
    /// Returns error if stack depth or types don't match.
    pub fn verify_types(&self, expected: &[CilFlavor]) -> Result<()> {
        if self.values.len() != expected.len() {
            return Err(EmulationError::InvalidStackState {
                message: format!(
                    "stack depth mismatch: expected {}, found {}",
                    expected.len(),
                    self.values.len()
                ),
            }
            .into());
        }

        for (i, (value, exp)) in self.values.iter().zip(expected.iter()).enumerate() {
            let actual = value.cil_flavor();
            if !actual.is_compatible_with(exp) {
                return Err(EmulationError::InvalidStackState {
                    message: format!(
                        "type mismatch at position {i}: expected {exp}, found {actual}"
                    ),
                }
                .into());
            }
        }

        Ok(())
    }
}

impl Default for EvaluationStack {
    fn default() -> Self {
        Self::default_depth()
    }
}

impl fmt::Display for EvaluationStack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Stack[")?;
        for (i, value) in self.values.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{value}")?;
        }
        write!(f, "]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{emulation::HeapRef, Error};

    #[test]
    fn test_stack_push_pop() {
        let mut stack = EvaluationStack::new(10);

        stack.push(EmValue::I32(1)).unwrap();
        stack.push(EmValue::I32(2)).unwrap();
        stack.push(EmValue::I32(3)).unwrap();

        assert_eq!(stack.depth(), 3);
        assert_eq!(stack.pop().unwrap(), EmValue::I32(3));
        assert_eq!(stack.pop().unwrap(), EmValue::I32(2));
        assert_eq!(stack.pop().unwrap(), EmValue::I32(1));
        assert!(stack.is_empty());
    }

    #[test]
    fn test_stack_overflow() {
        let mut stack = EvaluationStack::new(2);

        stack.push(EmValue::I32(1)).unwrap();
        stack.push(EmValue::I32(2)).unwrap();

        let result = stack.push(EmValue::I32(3));
        assert!(matches!(
            result,
            Err(Error::Emulation(ref e)) if matches!(e.as_ref(), EmulationError::StackOverflow)
        ));
    }

    #[test]
    fn test_stack_underflow() {
        let mut stack = EvaluationStack::new(10);

        let result = stack.pop();
        assert!(matches!(
            result,
            Err(Error::Emulation(ref e)) if matches!(e.as_ref(), EmulationError::StackUnderflow)
        ));
    }

    #[test]
    fn test_stack_peek() {
        let mut stack = EvaluationStack::new(10);

        stack.push(EmValue::I32(42)).unwrap();

        assert_eq!(stack.peek().unwrap(), &EmValue::I32(42));
        assert_eq!(stack.depth(), 1); // Peek doesn't remove
    }

    #[test]
    fn test_stack_peek_at() {
        let mut stack = EvaluationStack::new(10);

        stack.push(EmValue::I32(1)).unwrap();
        stack.push(EmValue::I32(2)).unwrap();
        stack.push(EmValue::I32(3)).unwrap();

        assert_eq!(stack.peek_at(0).unwrap(), &EmValue::I32(3)); // Top
        assert_eq!(stack.peek_at(1).unwrap(), &EmValue::I32(2));
        assert_eq!(stack.peek_at(2).unwrap(), &EmValue::I32(1)); // Bottom
        assert!(stack.peek_at(3).is_err());
    }

    #[test]
    fn test_stack_pop_typed() {
        let mut stack = EvaluationStack::new(10);

        stack.push(EmValue::I32(42)).unwrap();

        let value = stack.pop_typed(&CilFlavor::I4).unwrap();
        assert_eq!(value, EmValue::I32(42));

        stack.push(EmValue::I64(100)).unwrap();
        let result = stack.pop_typed(&CilFlavor::I4);
        assert!(matches!(
            result,
            Err(Error::Emulation(ref e)) if matches!(e.as_ref(), EmulationError::StackTypeMismatch { .. })
        ));
        // Value should be put back
        assert_eq!(stack.depth(), 1);
    }

    #[test]
    fn test_stack_pop_i32() {
        let mut stack = EvaluationStack::new(10);

        stack.push(EmValue::I32(42)).unwrap();
        assert_eq!(stack.pop_i32().unwrap(), 42);

        stack.push(EmValue::Bool(true)).unwrap();
        assert_eq!(stack.pop_i32().unwrap(), 1);

        stack.push(EmValue::Char('A')).unwrap();
        assert_eq!(stack.pop_i32().unwrap(), 65);

        stack.push(EmValue::I64(100)).unwrap();
        assert!(stack.pop_i32().is_err());
    }

    #[test]
    fn test_stack_pop_object_ref() {
        let mut stack = EvaluationStack::new(10);

        stack.push(EmValue::Null).unwrap();
        let val = stack.pop_object_ref().unwrap();
        assert_eq!(val, EmValue::Null);

        stack.push(EmValue::ObjectRef(HeapRef::new(1))).unwrap();
        let val = stack.pop_object_ref().unwrap();
        assert!(matches!(val, EmValue::ObjectRef(_)));

        stack.push(EmValue::I32(0)).unwrap();
        assert!(stack.pop_object_ref().is_err());
    }

    #[test]
    fn test_stack_pop_binary() {
        let mut stack = EvaluationStack::new(10);

        stack.push(EmValue::I32(10)).unwrap();
        stack.push(EmValue::I32(20)).unwrap();

        let (left, right) = stack.pop_binary().unwrap();
        assert_eq!(left, EmValue::I32(10));
        assert_eq!(right, EmValue::I32(20));
        assert!(stack.is_empty());
    }

    #[test]
    fn test_stack_dup() {
        let mut stack = EvaluationStack::new(10);

        stack.push(EmValue::I32(42)).unwrap();
        stack.dup().unwrap();

        assert_eq!(stack.depth(), 2);
        assert_eq!(stack.pop().unwrap(), EmValue::I32(42));
        assert_eq!(stack.pop().unwrap(), EmValue::I32(42));
    }

    #[test]
    fn test_stack_swap() {
        let mut stack = EvaluationStack::new(10);

        stack.push(EmValue::I32(1)).unwrap();
        stack.push(EmValue::I32(2)).unwrap();

        stack.swap().unwrap();

        assert_eq!(stack.pop().unwrap(), EmValue::I32(1));
        assert_eq!(stack.pop().unwrap(), EmValue::I32(2));
    }

    #[test]
    fn test_stack_clear() {
        let mut stack = EvaluationStack::new(10);

        stack.push(EmValue::I32(1)).unwrap();
        stack.push(EmValue::I32(2)).unwrap();

        stack.clear();
        assert!(stack.is_empty());
    }

    #[test]
    fn test_stack_snapshot_restore() {
        let mut stack = EvaluationStack::new(10);

        stack.push(EmValue::I32(1)).unwrap();
        stack.push(EmValue::I32(2)).unwrap();

        let snapshot = stack.snapshot();

        stack.push(EmValue::I32(3)).unwrap();
        assert_eq!(stack.depth(), 3);

        stack.restore(snapshot);
        assert_eq!(stack.depth(), 2);
    }

    #[test]
    fn test_stack_verify_types() {
        let mut stack = EvaluationStack::new(10);

        stack.push(EmValue::I32(1)).unwrap();
        stack.push(EmValue::I64(2)).unwrap();

        let result = stack.verify_types(&[CilFlavor::I4, CilFlavor::I8]);
        assert!(result.is_ok());

        let result = stack.verify_types(&[CilFlavor::I4, CilFlavor::I4]);
        assert!(result.is_err());

        let result = stack.verify_types(&[CilFlavor::I4]);
        assert!(result.is_err()); // Wrong depth
    }

    #[test]
    fn test_stack_display() {
        let mut stack = EvaluationStack::new(10);

        stack.push(EmValue::I32(1)).unwrap();
        stack.push(EmValue::I64(2)).unwrap();

        let display = format!("{stack}");
        assert!(display.contains("1"));
        assert!(display.contains("2L"));
    }
}

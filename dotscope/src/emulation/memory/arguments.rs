//! Method argument storage for CIL emulation.
//!
//! This module provides [`ArgumentStorage`] for managing method arguments during
//! CIL bytecode execution. Arguments are the values passed to a method call by
//! the caller and are accessible via `ldarg`, `starg`, and related instructions.
//!
//! # CIL Argument Semantics
//!
//! Unlike local variables, arguments are initialized by the caller before method
//! entry. For instance methods, argument 0 is implicitly the `this` reference.
//!
//! # Type Safety
//!
//! Argument storage tracks both values and their declared CIL types. The [`set`](ArgumentStorage::set)
//! method performs type checking using [`CilFlavor`]
//! compatibility rules, with relaxed checking for symbolic values used in analysis.

use std::fmt;

use crate::{
    emulation::{engine::EmulationError, EmValue},
    metadata::typesystem::CilFlavor,
    Result,
};

/// Storage for method arguments.
///
/// Arguments are passed to a method by the caller and can be read or modified
/// during method execution. For instance methods, argument 0 is typically `this`.
///
/// # Example
///
/// ```rust
/// use dotscope::emulation::{ArgumentStorage, EmValue};
/// use dotscope::metadata::typesystem::CilFlavor;
///
/// // Create arguments from caller's values
/// let mut args = ArgumentStorage::new(
///     vec![EmValue::I32(10), EmValue::I32(20)],
///     vec![CilFlavor::I4, CilFlavor::I4],
/// );
///
/// // Access arguments
/// assert_eq!(args.get(0).unwrap(), &EmValue::I32(10));
/// assert_eq!(args.get(1).unwrap(), &EmValue::I32(20));
///
/// // Modify argument (for ref/out parameters)
/// args.set(0, EmValue::I32(42)).unwrap();
/// ```
#[derive(Clone, Debug)]
pub struct ArgumentStorage {
    /// The argument values.
    values: Vec<EmValue>,

    /// The declared types for each argument.
    types: Vec<CilFlavor>,

    /// Whether this is an instance method (arg 0 is 'this').
    has_this: bool,
}

impl ArgumentStorage {
    /// Creates argument storage from caller values and types.
    ///
    /// # Arguments
    ///
    /// * `values` - Values passed by the caller
    /// * `types` - CIL type flavors for each argument
    ///
    /// # Panics
    ///
    /// Panics if values and types have different lengths.
    #[must_use]
    pub fn new(values: Vec<EmValue>, types: Vec<CilFlavor>) -> Self {
        assert_eq!(
            values.len(),
            types.len(),
            "values and types must have same length"
        );
        ArgumentStorage {
            values,
            types,
            has_this: false,
        }
    }

    /// Creates argument storage for an instance method.
    ///
    /// Argument 0 will be the `this` reference.
    ///
    /// # Arguments
    ///
    /// * `this_ref` - The 'this' object reference
    /// * `arg_values` - Additional argument values
    /// * `arg_types` - CIL type flavors for additional arguments
    #[must_use]
    pub fn with_this(
        this_ref: EmValue,
        arg_values: Vec<EmValue>,
        arg_types: Vec<CilFlavor>,
    ) -> Self {
        let mut values = vec![this_ref];
        values.extend(arg_values);

        let mut types = vec![CilFlavor::Object];
        types.extend(arg_types);

        ArgumentStorage {
            values,
            types,
            has_this: true,
        }
    }

    /// Creates empty argument storage.
    #[must_use]
    pub fn empty() -> Self {
        ArgumentStorage {
            values: Vec::new(),
            types: Vec::new(),
            has_this: false,
        }
    }

    /// Gets the value of an argument.
    ///
    /// # Arguments
    ///
    /// * `index` - The argument index (0-based)
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::ArgumentIndexOutOfBounds`] if index is out of bounds.
    pub fn get(&self, index: usize) -> Result<&EmValue> {
        let count = self.values.len();
        self.values
            .get(index)
            .ok_or_else(|| EmulationError::ArgumentIndexOutOfBounds { index, count }.into())
    }

    /// Gets a mutable reference to an argument.
    ///
    /// # Arguments
    ///
    /// * `index` - The argument index (0-based)
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::ArgumentIndexOutOfBounds`] if index is out of bounds.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut EmValue> {
        let count = self.values.len();
        self.values
            .get_mut(index)
            .ok_or_else(|| EmulationError::ArgumentIndexOutOfBounds { index, count }.into())
    }

    /// Sets the value of an argument.
    ///
    /// This is used for ref/out parameters that can be modified.
    ///
    /// # Arguments
    ///
    /// * `index` - The argument index (0-based)
    /// * `value` - The new value
    ///
    /// # Errors
    ///
    /// Returns error if index is out of bounds or type mismatches.
    pub fn set(&mut self, index: usize, value: EmValue) -> Result<()> {
        let count = self.values.len();
        let expected = self.types.get(index).ok_or_else(|| -> crate::Error {
            EmulationError::ArgumentIndexOutOfBounds { index, count }.into()
        })?;
        let found = value.cil_flavor();

        // Type check (relaxed for compatible types and symbolic values)
        if !expected.is_stack_assignable_from(&found) && !value.is_symbolic() {
            return Err(EmulationError::ArgumentFlavorMismatch {
                index,
                expected: Box::new(expected.clone()),
                found: Box::new(found),
            }
            .into());
        }

        let slot = self.values.get_mut(index).ok_or_else(|| -> crate::Error {
            EmulationError::ArgumentIndexOutOfBounds { index, count }.into()
        })?;
        *slot = value;
        Ok(())
    }

    /// Gets the type of an argument.
    ///
    /// # Arguments
    ///
    /// * `index` - The argument index (0-based)
    ///
    /// # Errors
    ///
    /// Returns error if index is out of bounds.
    pub fn get_type(&self, index: usize) -> Result<&CilFlavor> {
        let count = self.types.len();
        self.types
            .get(index)
            .ok_or_else(|| EmulationError::ArgumentIndexOutOfBounds { index, count }.into())
    }

    /// Gets the `this` reference for instance methods.
    ///
    /// # Returns
    ///
    /// `Some(&EmValue)` if this is an instance method, `None` otherwise.
    #[must_use]
    pub fn this(&self) -> Option<&EmValue> {
        if self.has_this {
            self.values.first()
        } else {
            None
        }
    }

    /// Returns `true` if this is an instance method.
    #[must_use]
    pub fn has_this(&self) -> bool {
        self.has_this
    }

    /// Returns the number of arguments.
    #[must_use]
    pub fn count(&self) -> usize {
        self.values.len()
    }

    /// Returns `true` if there are no arguments.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Returns a slice of all argument values.
    #[must_use]
    pub fn values(&self) -> &[EmValue] {
        &self.values
    }

    /// Returns a slice of all argument types.
    #[must_use]
    pub fn types(&self) -> &[CilFlavor] {
        &self.types
    }

    /// Returns an iterator over (index, value) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (usize, &EmValue)> {
        self.values.iter().enumerate()
    }

    /// Creates a snapshot of the current argument state.
    #[must_use]
    pub fn snapshot(&self) -> Vec<EmValue> {
        self.values.clone()
    }

    /// Restores arguments from a previous snapshot.
    ///
    /// # Panics
    ///
    /// Panics if snapshot length doesn't match argument count.
    pub fn restore(&mut self, snapshot: Vec<EmValue>) {
        assert_eq!(snapshot.len(), self.values.len(), "snapshot size mismatch");
        self.values = snapshot;
    }
}

impl Default for ArgumentStorage {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Display for ArgumentStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Args[")?;
        for (i, (value, typ)) in self.values.iter().zip(self.types.iter()).enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            if i == 0 && self.has_this {
                write!(f, "this={value}")?;
            } else {
                write!(f, "{i}:{typ:?}={value}")?;
            }
        }
        write!(f, "]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{emulation::HeapRef, Error};

    #[test]
    fn test_arguments_creation() {
        let args = ArgumentStorage::new(
            vec![EmValue::I32(10), EmValue::I32(20)],
            vec![CilFlavor::I4, CilFlavor::I4],
        );

        assert_eq!(args.count(), 2);
        assert_eq!(args.get(0).unwrap(), &EmValue::I32(10));
        assert_eq!(args.get(1).unwrap(), &EmValue::I32(20));
        assert!(!args.has_this());
    }

    #[test]
    fn test_arguments_with_this() {
        let this_ref = EmValue::ObjectRef(HeapRef::new(1));
        let args = ArgumentStorage::with_this(
            this_ref.clone(),
            vec![EmValue::I32(42)],
            vec![CilFlavor::I4],
        );

        assert!(args.has_this());
        assert_eq!(args.count(), 2);
        assert_eq!(args.this().unwrap(), &this_ref);
        assert_eq!(args.get(1).unwrap(), &EmValue::I32(42));
    }

    #[test]
    fn test_arguments_empty() {
        let args = ArgumentStorage::empty();
        assert!(args.is_empty());
        assert!(!args.has_this());
    }

    #[test]
    fn test_arguments_get_set() {
        let mut args = ArgumentStorage::new(vec![EmValue::I32(10)], vec![CilFlavor::I4]);

        args.set(0, EmValue::I32(42)).unwrap();
        assert_eq!(args.get(0).unwrap(), &EmValue::I32(42));
    }

    #[test]
    fn test_arguments_out_of_bounds() {
        let args = ArgumentStorage::new(vec![EmValue::I32(10)], vec![CilFlavor::I4]);

        assert!(matches!(
            args.get(5),
            Err(Error::Emulation(ref e)) if matches!(e.as_ref(), EmulationError::ArgumentIndexOutOfBounds { .. })
        ));
    }

    #[test]
    fn test_arguments_type_mismatch() {
        let mut args = ArgumentStorage::new(vec![EmValue::I32(10)], vec![CilFlavor::I4]);

        let result = args.set(0, EmValue::I64(100));
        assert!(matches!(
            result,
            Err(Error::Emulation(ref e)) if matches!(e.as_ref(), EmulationError::ArgumentFlavorMismatch { .. })
        ));
    }

    #[test]
    fn test_arguments_get_type() {
        let args = ArgumentStorage::new(
            vec![EmValue::I32(10), EmValue::I64(20)],
            vec![CilFlavor::I4, CilFlavor::I8],
        );

        assert_eq!(args.get_type(0).unwrap(), &CilFlavor::I4);
        assert_eq!(args.get_type(1).unwrap(), &CilFlavor::I8);
    }

    #[test]
    fn test_arguments_snapshot_restore() {
        let mut args = ArgumentStorage::new(vec![EmValue::I32(10)], vec![CilFlavor::I4]);

        let snapshot = args.snapshot();
        args.set(0, EmValue::I32(99)).unwrap();

        args.restore(snapshot);
        assert_eq!(args.get(0).unwrap(), &EmValue::I32(10));
    }

    #[test]
    fn test_arguments_iter() {
        let args = ArgumentStorage::new(
            vec![EmValue::I32(10), EmValue::I32(20)],
            vec![CilFlavor::I4, CilFlavor::I4],
        );

        let items: Vec<_> = args.iter().collect();
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn test_arguments_display() {
        let args = ArgumentStorage::new(vec![EmValue::I32(42)], vec![CilFlavor::I4]);

        let display = format!("{args}");
        assert!(display.contains("42"));
    }
}

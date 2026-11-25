//! Local variable storage for CIL emulation.
//!
//! This module provides [`LocalVariables`] for managing method-local storage
//! during CIL bytecode execution. Local variables are declared in the method's
//! local signature and are accessible via `ldloc`, `stloc`, and related instructions.
//!
//! # CIL Local Variable Semantics
//!
//! Local variables provide method-scoped storage slots that persist for the
//! duration of a method call. Each local has a declared type and is initialized
//! to its default value (zero, null, or default struct) at method entry.
//!
//! # Type Safety
//!
//! Local variable storage tracks both values and their declared CIL types.
//! The [`set`](LocalVariables::set) method performs type checking using
//! [`CilFlavor`] compatibility rules,
//! with relaxed checking for symbolic values used in analysis.

use std::fmt;

use crate::{
    emulation::{engine::EmulationError, EmValue},
    metadata::typesystem::CilFlavor,
    Result,
};

/// Storage for method local variables.
///
/// Local variables are defined by the method metadata and persist for the
/// duration of the method call. They are initialized to default values
/// based on their type.
///
/// # Example
///
/// ```rust
/// use dotscope::emulation::{EmValue, LocalVariables};
/// use dotscope::metadata::typesystem::CilFlavor;
///
/// // Create locals from type information
/// let mut locals = LocalVariables::new(vec![
///     CilFlavor::I4,
///     CilFlavor::I8,
///     CilFlavor::Object,
/// ]);
///
/// // Load default values
/// assert_eq!(locals.get(0).unwrap(), &EmValue::I32(0));
/// assert_eq!(locals.get(2).unwrap(), &EmValue::Null);
///
/// // Store and load
/// locals.set(0, EmValue::I32(42)).unwrap();
/// assert_eq!(locals.get(0).unwrap(), &EmValue::I32(42));
/// ```
#[derive(Clone, Debug)]
pub struct LocalVariables {
    /// The local variable values.
    values: Vec<EmValue>,

    /// The declared types for each local.
    types: Vec<CilFlavor>,
}

impl LocalVariables {
    /// Creates local variables from their type definitions.
    ///
    /// Each local is initialized to its default value based on type.
    ///
    /// # Arguments
    ///
    /// * `types` - CIL type flavors for each local variable
    #[must_use]
    pub fn new(types: Vec<CilFlavor>) -> Self {
        let values = types.iter().map(EmValue::default_for_flavor).collect();

        LocalVariables { values, types }
    }

    /// Creates an empty local variable storage.
    #[must_use]
    pub fn empty() -> Self {
        LocalVariables {
            values: Vec::new(),
            types: Vec::new(),
        }
    }

    /// Creates local variables with explicit initial values.
    ///
    /// # Arguments
    ///
    /// * `values` - Initial values for each local
    /// * `types` - CIL type flavors for each local (must match values length)
    ///
    /// # Panics
    ///
    /// Panics if values and types have different lengths.
    #[must_use]
    pub fn with_values(values: Vec<EmValue>, types: Vec<CilFlavor>) -> Self {
        assert_eq!(
            values.len(),
            types.len(),
            "values and types must have same length"
        );
        LocalVariables { values, types }
    }

    /// Gets the value of a local variable.
    ///
    /// # Arguments
    ///
    /// * `index` - The local variable index (0-based)
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LocalIndexOutOfBounds`] if index is invalid.
    pub fn get(&self, index: usize) -> Result<&EmValue> {
        let count = self.values.len();
        self.values
            .get(index)
            .ok_or_else(|| EmulationError::LocalIndexOutOfBounds { index, count }.into())
    }

    /// Gets a mutable reference to a local variable.
    ///
    /// # Arguments
    ///
    /// * `index` - The local variable index (0-based)
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LocalIndexOutOfBounds`] if index is invalid.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut EmValue> {
        let count = self.values.len();
        self.values
            .get_mut(index)
            .ok_or_else(|| EmulationError::LocalIndexOutOfBounds { index, count }.into())
    }

    /// Sets the value of a local variable.
    ///
    /// # Arguments
    ///
    /// * `index` - The local variable index (0-based)
    /// * `value` - The value to store
    ///
    /// # Errors
    ///
    /// Returns error if index is out of bounds.
    ///
    /// # Type handling
    ///
    /// Matches .NET CLR runtime behavior: local variable types are NOT enforced
    /// at execution time. The CLR only checks types during optional verification
    /// (peverify), not at runtime. This is important for obfuscated code (e.g.,
    /// CFF-protected methods) which is always unverifiable and may store different
    /// types into the same local across different code paths.
    ///
    /// When a type mismatch is detected, the local's declared type is updated to
    /// match the stored value, ensuring subsequent loads work correctly.
    pub fn set(&mut self, index: usize, value: EmValue) -> Result<()> {
        let count = self.values.len();
        let slot = self.values.get_mut(index).ok_or_else(|| -> crate::Error {
            EmulationError::LocalIndexOutOfBounds { index, count }.into()
        })?;

        // Match .NET runtime behavior: accept all types for local stores.
        // If the stored value's type differs from the declared type, update the
        // declared type to match. This handles unverifiable code patterns like
        // CFF obfuscation where different code paths store different types.
        if !value.is_symbolic() {
            let found = value.cil_flavor();
            let type_slot = self.types.get_mut(index).ok_or_else(|| -> crate::Error {
                EmulationError::LocalIndexOutOfBounds { index, count }.into()
            })?;
            if !type_slot.is_stack_assignable_from(&found) {
                *type_slot = found;
            }
        }

        *slot = value;
        Ok(())
    }

    /// Gets the declared type of a local variable.
    ///
    /// # Arguments
    ///
    /// * `index` - The local variable index (0-based)
    ///
    /// # Errors
    ///
    /// Returns error if index is invalid.
    pub fn get_type(&self, index: usize) -> Result<&CilFlavor> {
        let count = self.types.len();
        self.types
            .get(index)
            .ok_or_else(|| EmulationError::LocalIndexOutOfBounds { index, count }.into())
    }

    /// Returns the number of local variables.
    #[must_use]
    pub fn count(&self) -> usize {
        self.values.len()
    }

    /// Returns `true` if there are no local variables.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Returns a slice of all local values.
    #[must_use]
    pub fn values(&self) -> &[EmValue] {
        &self.values
    }

    /// Returns a slice of all local types.
    #[must_use]
    pub fn types(&self) -> &[CilFlavor] {
        &self.types
    }

    /// Resets all locals to their default values.
    pub fn reset(&mut self) {
        for (value, typ) in self.values.iter_mut().zip(self.types.iter()) {
            *value = EmValue::default_for_flavor(typ);
        }
    }

    /// Creates a snapshot of the current local variable state.
    #[must_use]
    pub fn snapshot(&self) -> Vec<EmValue> {
        self.values.clone()
    }

    /// Restores locals from a previous snapshot.
    ///
    /// # Panics
    ///
    /// Panics if snapshot length doesn't match local count.
    pub fn restore(&mut self, snapshot: Vec<EmValue>) {
        assert_eq!(snapshot.len(), self.values.len(), "snapshot size mismatch");
        self.values = snapshot;
    }

    /// Returns an iterator over (index, value) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (usize, &EmValue)> {
        self.values.iter().enumerate()
    }

    /// Returns an iterator over (index, type, value) triples.
    pub fn iter_typed(&self) -> impl Iterator<Item = (usize, &CilFlavor, &EmValue)> {
        self.values
            .iter()
            .zip(self.types.iter())
            .enumerate()
            .map(|(i, (v, t))| (i, t, v))
    }
}

impl Default for LocalVariables {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Display for LocalVariables {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Locals[")?;
        for (i, (value, typ)) in self.values.iter().zip(self.types.iter()).enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{i}:{typ:?}={value}")?;
        }
        write!(f, "]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    #[test]
    fn test_locals_creation() {
        let locals = LocalVariables::new(vec![CilFlavor::I4, CilFlavor::I8, CilFlavor::Object]);

        assert_eq!(locals.count(), 3);
        assert_eq!(locals.get(0).unwrap(), &EmValue::I32(0));
        assert_eq!(locals.get(1).unwrap(), &EmValue::I64(0));
        assert_eq!(locals.get(2).unwrap(), &EmValue::Null);
    }

    #[test]
    fn test_locals_empty() {
        let locals = LocalVariables::empty();
        assert!(locals.is_empty());
        assert_eq!(locals.count(), 0);
    }

    #[test]
    fn test_locals_get_set() {
        let mut locals = LocalVariables::new(vec![CilFlavor::I4, CilFlavor::I8]);

        locals.set(0, EmValue::I32(42)).unwrap();
        assert_eq!(locals.get(0).unwrap(), &EmValue::I32(42));

        locals.set(1, EmValue::I64(100)).unwrap();
        assert_eq!(locals.get(1).unwrap(), &EmValue::I64(100));
    }

    #[test]
    fn test_locals_out_of_bounds() {
        let locals = LocalVariables::new(vec![CilFlavor::I4]);

        let result = locals.get(5);
        assert!(matches!(
            result,
            Err(Error::Emulation(ref e)) if matches!(e.as_ref(), EmulationError::LocalIndexOutOfBounds { index: 5, count: 1 })
        ));
    }

    #[test]
    fn test_locals_type_mismatch_accepted() {
        // Matches .NET CLR runtime behavior: local type mismatches are accepted.
        // The CLR only checks types during optional verification, not at runtime.
        let mut locals = LocalVariables::new(vec![CilFlavor::I4]);

        // Storing I64 into I4 local should succeed (type updated to match)
        let result = locals.set(0, EmValue::I64(100));
        assert!(result.is_ok());
        assert_eq!(locals.get(0).unwrap(), &EmValue::I64(100));
        assert_eq!(locals.get_type(0).unwrap(), &CilFlavor::I8);
    }

    #[test]
    fn test_locals_get_type() {
        let locals = LocalVariables::new(vec![CilFlavor::I4, CilFlavor::R8]);

        assert_eq!(locals.get_type(0).unwrap(), &CilFlavor::I4);
        assert_eq!(locals.get_type(1).unwrap(), &CilFlavor::R8);
    }

    #[test]
    fn test_locals_reset() {
        let mut locals = LocalVariables::new(vec![CilFlavor::I4, CilFlavor::I8]);

        locals.set(0, EmValue::I32(42)).unwrap();
        locals.set(1, EmValue::I64(100)).unwrap();

        locals.reset();

        assert_eq!(locals.get(0).unwrap(), &EmValue::I32(0));
        assert_eq!(locals.get(1).unwrap(), &EmValue::I64(0));
    }

    #[test]
    fn test_locals_snapshot_restore() {
        let mut locals = LocalVariables::new(vec![CilFlavor::I4, CilFlavor::I8]);

        locals.set(0, EmValue::I32(42)).unwrap();
        let snapshot = locals.snapshot();

        locals.set(0, EmValue::I32(99)).unwrap();
        assert_eq!(locals.get(0).unwrap(), &EmValue::I32(99));

        locals.restore(snapshot);
        assert_eq!(locals.get(0).unwrap(), &EmValue::I32(42));
    }

    #[test]
    fn test_locals_iter() {
        let locals = LocalVariables::new(vec![CilFlavor::I4, CilFlavor::I8]);

        let items: Vec<_> = locals.iter().collect();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], (0, &EmValue::I32(0)));
        assert_eq!(items[1], (1, &EmValue::I64(0)));
    }

    #[test]
    fn test_locals_display() {
        let mut locals = LocalVariables::new(vec![CilFlavor::I4]);
        locals.set(0, EmValue::I32(42)).unwrap();

        let display = format!("{locals}");
        assert!(display.contains("42"));
    }

    #[test]
    fn test_locals_error_display() {
        let err = EmulationError::LocalIndexOutOfBounds { index: 5, count: 3 };
        assert!(format!("{err}").contains("5"));
        assert!(format!("{err}").contains("3"));
    }
}

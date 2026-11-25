//! Static field storage for CIL emulation.
//!
//! This module provides [`StaticFieldStorage`] for managing static (class-level)
//! fields during CIL bytecode execution. Static fields are accessed via
//! `ldsfld` and `stsfld` instructions.
//!
//! # Static Field Semantics
//!
//! Static fields are shared across all instances of a type and persist for
//! the lifetime of the emulated process. They are initialized when first
//! accessed or when the type's static constructor (`.cctor`) is run.
//!
//! # Thread Safety
//!
//! All operations use interior mutability via `RwLock` for thread-safe access.
//!
//! # Copy-on-Write Semantics
//!
//! The storage uses `imbl::HashMap` and `imbl::HashSet` for O(1) fork operations.
//! When you call `fork()`, both the original and the fork share the same underlying
//! data structure via structural sharing. Only modified entries are copied.
//!
//! # Type Initialization Tracking
//!
//! The storage tracks which types have had their static constructors run via
//! [`is_type_initialized`](StaticFieldStorage::is_type_initialized) and
//! [`mark_type_initialized`](StaticFieldStorage::mark_type_initialized).

use std::sync::{Arc, RwLock};

use imbl::HashMap as ImHashMap;

use crate::{
    emulation::{engine::EmulationError, EmValue},
    metadata::token::Token,
    Result,
};

/// Tracks the initialization state of a type's static constructor.
///
/// Per ECMA-335 §II.10.5.3.3, type initialization follows a three-state model:
/// - `Uninitialized` — .cctor has not been triggered
/// - `InProgress` — .cctor is currently executing (re-entrant access skips)
/// - `Initialized` — .cctor completed (or the type has no .cctor)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypeInitState {
    /// The type's static constructor has not yet been triggered.
    Uninitialized,
    /// The type's static constructor is currently executing.
    /// Re-entrant access from the same thread should be allowed (skip .cctor).
    InProgress,
    /// The type's static constructor has completed (successfully or with failure).
    Initialized,
}

/// Storage for static fields in the emulated process.
///
/// Static fields are stored by their field token and persist across method
/// calls and thread boundaries. This structure also tracks which types have
/// had their static constructors (`.cctor`) executed.
///
/// # Thread Safety
///
/// All operations use interior mutability via `RwLock`, allowing safe
/// concurrent access from multiple threads.
///
/// # Copy-on-Write
///
/// The storage uses `imbl` persistent data structures internally, enabling
/// O(1) `fork()` operations via structural sharing.
///
/// # Example
///
/// ```rust
/// use dotscope::emulation::{StaticFieldStorage, EmValue};
/// use dotscope::metadata::token::Token;
///
/// let storage = StaticFieldStorage::new();
///
/// // Store a static field
/// let field_token = Token::new(0x04000001);
/// storage.set(field_token, EmValue::I32(42)).unwrap();
///
/// // Retrieve it later
/// assert_eq!(storage.get(field_token).unwrap(), Some(EmValue::I32(42)));
///
/// // Fork creates an independent copy (O(1) operation!)
/// let forked = storage.fork().unwrap();
/// forked.set(field_token, EmValue::I32(100)).unwrap();
/// // Original is unchanged
/// assert_eq!(storage.get(field_token).unwrap(), Some(EmValue::I32(42)));
/// ```
#[derive(Debug)]
pub struct StaticFieldStorage {
    /// Static fields indexed by field token.
    /// Uses imbl::HashMap for O(1) fork via structural sharing. Each value sits behind an
    /// `Arc`, so the first write after a fork copies the map node it lies in without copying
    /// the values beside it (a value type's fields among them).
    fields: RwLock<ImHashMap<Token, Arc<EmValue>>>,

    /// Tracks type initialization state using a three-state model.
    /// Uses imbl::HashMap for O(1) fork via structural sharing.
    type_init_state: RwLock<ImHashMap<Token, TypeInitState>>,
}

impl StaticFieldStorage {
    /// Creates new empty static field storage.
    #[must_use]
    pub fn new() -> Self {
        Self {
            fields: RwLock::new(ImHashMap::new()),
            type_init_state: RwLock::new(ImHashMap::new()),
        }
    }

    /// Gets a static field value.
    ///
    /// # Arguments
    ///
    /// * `field_token` - The metadata token of the field
    ///
    /// # Returns
    ///
    /// `Some(EmValue)` if the field exists, `None` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the fields lock is poisoned.
    pub fn get(&self, field_token: Token) -> Result<Option<EmValue>> {
        let fields = self
            .fields
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "static field storage",
            })?;
        Ok(fields.get(&field_token).map(|value| EmValue::clone(value)))
    }

    /// Sets a static field value.
    ///
    /// If the field already exists, its value is replaced.
    ///
    /// # Arguments
    ///
    /// * `field_token` - The metadata token of the field
    /// * `value` - The value to store
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the fields lock is poisoned.
    pub fn set(&self, field_token: Token, value: EmValue) -> Result<()> {
        let mut fields = self
            .fields
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "static field storage",
            })?;
        fields.insert(field_token, Arc::new(value));
        Ok(())
    }

    /// Returns `true` if the static field exists.
    ///
    /// # Arguments
    ///
    /// * `field_token` - The metadata token of the field
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the fields lock is poisoned.
    pub fn contains(&self, field_token: Token) -> Result<bool> {
        let fields = self
            .fields
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "static field storage",
            })?;
        Ok(fields.contains_key(&field_token))
    }

    /// Removes a static field and returns its value.
    ///
    /// # Arguments
    ///
    /// * `field_token` - The metadata token of the field
    ///
    /// # Returns
    ///
    /// The removed value, or `None` if the field didn't exist.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the fields lock is poisoned.
    pub fn remove(&self, field_token: Token) -> Result<Option<EmValue>> {
        let mut fields = self
            .fields
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "static field storage",
            })?;
        Ok(fields.remove(&field_token).map(Arc::unwrap_or_clone))
    }

    /// Returns `true` if the type's static constructor has been run or is currently running.
    ///
    /// This is used to implement the `.cctor` execution semantics where
    /// static constructors run at most once per type. Returns `true` for both
    /// `InProgress` and `Initialized` states (ECMA-335 §II.10.5.3.3: re-entrant
    /// access during .cctor execution is allowed without re-running .cctor).
    ///
    /// # Arguments
    ///
    /// * `type_token` - The type's metadata token
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the type init state lock is poisoned.
    pub fn is_type_initialized(&self, type_token: Token) -> Result<bool> {
        let state = self
            .type_init_state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "static field storage",
            })?;
        Ok(matches!(
            state.get(&type_token),
            Some(TypeInitState::InProgress | TypeInitState::Initialized)
        ))
    }

    /// Returns the current initialization state of a type.
    ///
    /// # Arguments
    ///
    /// * `type_token` - The type's metadata token
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the type init state lock is poisoned.
    pub fn type_init_state(&self, type_token: Token) -> Result<TypeInitState> {
        let state = self
            .type_init_state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "static field storage",
            })?;
        Ok(state
            .get(&type_token)
            .copied()
            .unwrap_or(TypeInitState::Uninitialized))
    }

    /// Sets a type's initialization state.
    ///
    /// # Arguments
    ///
    /// * `type_token` - The type's metadata token
    /// * `state` - The new initialization state
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the type init state lock is poisoned.
    pub fn set_type_init_state(&self, type_token: Token, init_state: TypeInitState) -> Result<()> {
        let mut state = self
            .type_init_state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "static field storage",
            })?;
        state.insert(type_token, init_state);
        Ok(())
    }

    /// Marks a type as having had its static constructor run.
    ///
    /// Call this after successfully executing a type's `.cctor` method.
    /// This sets the state to `Initialized`.
    ///
    /// # Arguments
    ///
    /// * `type_token` - The type's metadata token
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the type init state lock is poisoned.
    pub fn mark_type_initialized(&self, type_token: Token) -> Result<()> {
        self.set_type_init_state(type_token, TypeInitState::Initialized)
    }

    /// Clears all static fields and initialization state.
    ///
    /// This resets the storage to its initial empty state, useful for
    /// testing or resetting the emulator.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if any lock is poisoned.
    pub fn clear(&self) -> Result<()> {
        let mut fields = self
            .fields
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "static field storage",
            })?;
        let mut state = self
            .type_init_state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "static field storage",
            })?;
        fields.clear();
        state.clear();
        Ok(())
    }

    /// Returns the number of static fields stored.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the fields lock is poisoned.
    pub fn len(&self) -> Result<usize> {
        let fields = self
            .fields
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "static field storage",
            })?;
        Ok(fields.len())
    }

    /// Returns `true` if no static fields are stored.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the fields lock is poisoned.
    pub fn is_empty(&self) -> Result<bool> {
        let fields = self
            .fields
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "static field storage",
            })?;
        Ok(fields.is_empty())
    }

    /// Returns all stored field tokens.
    ///
    /// Useful for debugging and diagnostics.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the fields lock is poisoned.
    pub fn field_tokens(&self) -> Result<Vec<Token>> {
        let fields = self
            .fields
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "static field storage",
            })?;
        Ok(fields.keys().copied().collect())
    }

    /// Returns all type tokens that have been marked as initialized.
    ///
    /// Useful for debugging and diagnostics.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the type init state lock is poisoned.
    pub fn initialized_types(&self) -> Result<Vec<Token>> {
        let state = self
            .type_init_state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "static field storage",
            })?;
        Ok(state
            .iter()
            .filter(|(_, s)| matches!(s, TypeInitState::Initialized))
            .map(|(t, _)| *t)
            .collect())
    }

    /// Forks this storage, creating an independent copy with CoW semantics.
    ///
    /// The forked storage shares its data structure with the original via
    /// structural sharing. Both storages can be modified independently -
    /// only the modified entries are copied (true copy-on-write).
    ///
    /// # Performance
    ///
    /// This is an O(1) operation due to `imbl`'s structural sharing.
    /// The actual data is only copied when either storage modifies an entry.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if any lock is poisoned.
    pub fn fork(&self) -> Result<Self> {
        let fields = self
            .fields
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "static field storage",
            })?;
        let state = self
            .type_init_state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "static field storage",
            })?;
        Ok(Self {
            // imbl::HashMap::clone() is O(1) - structural sharing!
            fields: RwLock::new(fields.clone()),
            type_init_state: RwLock::new(state.clone()),
        })
    }
}

impl Default for StaticFieldStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        emulation::{memory::statics::StaticFieldStorage, EmValue},
        metadata::token::Token,
    };

    #[test]
    fn test_static_field_storage() {
        let storage = StaticFieldStorage::new();
        let field = Token::new(0x04000001);

        // Initially empty
        assert!(storage.get(field).unwrap().is_none());
        assert!(!storage.contains(field).unwrap());

        // Set a value
        storage.set(field, EmValue::I32(42)).unwrap();
        assert!(storage.contains(field).unwrap());
        assert_eq!(storage.get(field).unwrap(), Some(EmValue::I32(42)));

        // Update the value
        storage.set(field, EmValue::I32(100)).unwrap();
        assert_eq!(storage.get(field).unwrap(), Some(EmValue::I32(100)));

        // Remove
        let removed = storage.remove(field).unwrap();
        assert_eq!(removed, Some(EmValue::I32(100)));
        assert!(storage.get(field).unwrap().is_none());
    }

    #[test]
    fn test_type_initialization_tracking() {
        let storage = StaticFieldStorage::new();
        let type_token = Token::new(0x02000001);

        // Initially not initialized
        assert!(!storage.is_type_initialized(type_token).unwrap());

        // Mark as initialized
        storage.mark_type_initialized(type_token).unwrap();
        assert!(storage.is_type_initialized(type_token).unwrap());

        // Check we can get the list
        let initialized = storage.initialized_types().unwrap();
        assert!(initialized.contains(&type_token));
    }

    #[test]
    fn test_clear() {
        let storage = StaticFieldStorage::new();
        let field = Token::new(0x04000001);
        let type_token = Token::new(0x02000001);

        storage.set(field, EmValue::I32(42)).unwrap();
        storage.mark_type_initialized(type_token).unwrap();

        assert!(!storage.is_empty().unwrap());

        storage.clear().unwrap();

        assert!(storage.is_empty().unwrap());
        assert!(!storage.is_type_initialized(type_token).unwrap());
    }

    #[test]
    fn test_fork() {
        let storage = StaticFieldStorage::new();
        let field1 = Token::new(0x04000001);
        let field2 = Token::new(0x04000002);
        let type_token = Token::new(0x02000001);

        // Set up original
        storage.set(field1, EmValue::I32(42)).unwrap();
        storage.mark_type_initialized(type_token).unwrap();

        // Fork
        let forked = storage.fork().unwrap();

        // Both see the same data
        assert_eq!(storage.get(field1).unwrap(), Some(EmValue::I32(42)));
        assert_eq!(forked.get(field1).unwrap(), Some(EmValue::I32(42)));
        assert!(storage.is_type_initialized(type_token).unwrap());
        assert!(forked.is_type_initialized(type_token).unwrap());

        // Modify forked
        forked.set(field1, EmValue::I32(100)).unwrap();
        forked.set(field2, EmValue::I32(200)).unwrap();

        // Original is unchanged
        assert_eq!(storage.get(field1).unwrap(), Some(EmValue::I32(42)));
        assert!(storage.get(field2).unwrap().is_none());

        // Forked has new values
        assert_eq!(forked.get(field1).unwrap(), Some(EmValue::I32(100)));
        assert_eq!(forked.get(field2).unwrap(), Some(EmValue::I32(200)));
    }

    #[test]
    fn test_fork_isolation() {
        let storage = StaticFieldStorage::new();
        let field = Token::new(0x04000001);
        storage.set(field, EmValue::I32(1)).unwrap();

        // Create multiple forks
        let fork1 = storage.fork().unwrap();
        let fork2 = storage.fork().unwrap();

        // Modify each independently
        fork1.set(field, EmValue::I32(10)).unwrap();
        fork2.set(field, EmValue::I32(20)).unwrap();

        // Each has its own value
        assert_eq!(storage.get(field).unwrap(), Some(EmValue::I32(1)));
        assert_eq!(fork1.get(field).unwrap(), Some(EmValue::I32(10)));
        assert_eq!(fork2.get(field).unwrap(), Some(EmValue::I32(20)));
    }
}

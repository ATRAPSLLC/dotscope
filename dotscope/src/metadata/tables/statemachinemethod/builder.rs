//! Builder for constructing `StateMachineMethod` table entries
//!
//! This module provides the [`crate::metadata::tables::statemachinemethod::StateMachineMethodBuilder`] which enables fluent construction
//! of `StateMachineMethod` metadata table entries. The builder follows the established
//! pattern used across all table builders in the library.
//!
//! # Usage Example
//!
//! ```rust,no_run
//! use dotscope::prelude::*;
//!
//! # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
//! let mut assembly = CilAssembly::new(view);
//!
//! let mapping_token = StateMachineMethodBuilder::new()
//!     .move_next_method(123)         // MethodDef RID for MoveNext method
//!     .kickoff_method(45)            // MethodDef RID for original method
//!     .build(&mut assembly)?;
//! # Ok::<(), dotscope::Error>(())
//! ```

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{StateMachineMethodRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for constructing `StateMachineMethod` table entries
///
/// Provides a fluent interface for building `StateMachineMethod` metadata table entries.
/// These entries map compiler-generated state machine methods back to their original
/// user-written methods, enabling proper debugging of async/await and iterator methods.
///
/// # Required Fields
/// - `move_next_method`: MethodDef RID for the compiler-generated MoveNext method
/// - `kickoff_method`: MethodDef RID for the original user-written method
///
/// # State Machine Context
///
/// When compilers generate state machines for async/await or yield return patterns:
/// 1. The original method becomes the "kickoff" method that initializes the state machine
/// 2. A new `MoveNext` method contains the actual implementation logic
/// 3. This table provides the bidirectional mapping between these methods
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
/// # let mut assembly = CilAssembly::new(view);
/// // Map async method to its state machine
/// let async_mapping = StateMachineMethodBuilder::new()
///     .move_next_method(123)  // Compiler-generated MoveNext method
///     .kickoff_method(45)     // Original async method
///     .build(&mut assembly)?;
///
/// // Map iterator method to its state machine
/// let iterator_mapping = StateMachineMethodBuilder::new()
///     .move_next_method(200)  // Compiler-generated MoveNext method
///     .kickoff_method(78)     // Original iterator method
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct StateMachineMethodBuilder {
    /// MethodDef RID for the compiler-generated MoveNext method
    move_next_method: Option<u32>,
    /// MethodDef RID for the original user-written method
    kickoff_method: Option<u32>,
}

impl StateMachineMethodBuilder {
    /// Creates a new `StateMachineMethodBuilder` with default values
    ///
    /// Initializes a new builder instance with all fields unset. The caller
    /// must provide both required fields before calling build().
    ///
    /// # Returns
    /// A new `StateMachineMethodBuilder` instance ready for configuration
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = StateMachineMethodBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            move_next_method: None,
            kickoff_method: None,
        }
    }

    /// Sets the MoveNext method RID
    ///
    /// Specifies the MethodDef RID for the compiler-generated MoveNext method
    /// that contains the actual state machine implementation logic.
    ///
    /// # Parameters
    /// - `move_next_method`: MethodDef RID for the MoveNext method
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = StateMachineMethodBuilder::new()
    ///     .move_next_method(123);  // RID of compiler-generated method
    /// ```
    #[must_use]
    pub fn move_next_method(mut self, move_next_method: u32) -> Self {
        self.move_next_method = Some(move_next_method);
        self
    }

    /// Sets the kickoff method RID
    ///
    /// Specifies the MethodDef RID for the original user-written method
    /// that was transformed into a state machine by the compiler.
    ///
    /// # Parameters
    /// - `kickoff_method`: MethodDef RID for the original method
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = StateMachineMethodBuilder::new()
    ///     .kickoff_method(45);  // RID of original user method
    /// ```
    #[must_use]
    pub fn kickoff_method(mut self, kickoff_method: u32) -> Self {
        self.kickoff_method = Some(kickoff_method);
        self
    }

    /// Builds and adds the `StateMachineMethod` entry to the metadata
    ///
    /// Validates all required fields, creates the `StateMachineMethod` table entry,
    /// and adds it to the assembly. Returns a token that can be used
    /// to reference this state machine method mapping.
    ///
    /// # Parameters
    /// - `assembly`: Mutable reference to the CilAssembly
    ///
    /// # Returns
    /// - `Ok(Token)`: Token referencing the created state machine method mapping
    /// - `Err(Error)`: If validation fails or table operations fail
    ///
    /// # Errors
    /// - Missing required field (move_next_method or kickoff_method)
    /// - Table operations fail due to metadata constraints
    /// - State machine method validation failed
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
    /// let mut assembly = CilAssembly::new(view);
    /// let token = StateMachineMethodBuilder::new()
    ///     .move_next_method(123)
    ///     .kickoff_method(45)
    ///     .build(&mut assembly)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let move_next_method = self.move_next_method.ok_or_else(|| {
            Error::ModificationInvalid(
                "MoveNext method RID is required for StateMachineMethod".to_string(),
            )
        })?;

        let kickoff_method = self.kickoff_method.ok_or_else(|| {
            Error::ModificationInvalid(
                "Kickoff method RID is required for StateMachineMethod".to_string(),
            )
        })?;

        let state_machine_method = StateMachineMethodRaw {
            rid: 0,
            token: Token::new(0),
            offset: 0,
            move_next_method,
            kickoff_method,
        };

        assembly.table_row_add(
            TableId::StateMachineMethod,
            TableDataOwned::StateMachineMethod(state_machine_method),
        )
    }
}

impl Default for StateMachineMethodBuilder {
    /// Creates a default `StateMachineMethodBuilder`
    ///
    /// Equivalent to calling [`StateMachineMethodBuilder::new()`].
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::testkit::factories::table::assemblyref::get_test_assembly;

    #[test]
    fn test_statemachinemethod_builder_new() {
        let builder = StateMachineMethodBuilder::new();

        assert!(builder.move_next_method.is_none());
        assert!(builder.kickoff_method.is_none());
    }

    #[test]
    fn test_statemachinemethod_builder_default() {
        let builder = StateMachineMethodBuilder::default();

        assert!(builder.move_next_method.is_none());
        assert!(builder.kickoff_method.is_none());
    }

    #[test]
    fn test_statemachinemethod_builder_basic() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let _change_ref = StateMachineMethodBuilder::new()
            .move_next_method(123)
            .kickoff_method(45)
            .build(&mut assembly)
            .expect("Should build successfully");

        Ok(())
    }

    #[test]
    fn test_statemachinemethod_builder_async_mapping() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let _change_ref = StateMachineMethodBuilder::new()
            .move_next_method(200) // Async state machine MoveNext
            .kickoff_method(78) // Original async method
            .build(&mut assembly)
            .expect("Should build successfully");

        Ok(())
    }

    #[test]
    fn test_statemachinemethod_builder_iterator_mapping() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let _change_ref = StateMachineMethodBuilder::new()
            .move_next_method(300) // Iterator state machine MoveNext
            .kickoff_method(99) // Original iterator method
            .build(&mut assembly)
            .expect("Should build successfully");

        Ok(())
    }

    #[test]
    fn test_statemachinemethod_builder_missing_move_next() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let result = StateMachineMethodBuilder::new()
            .kickoff_method(45)
            .build(&mut assembly);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalid(details) => {
                assert!(details.contains("MoveNext method RID is required"));
            }
            _ => panic!("Expected ModificationInvalid error"),
        }
        Ok(())
    }

    #[test]
    fn test_statemachinemethod_builder_missing_kickoff() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let result = StateMachineMethodBuilder::new()
            .move_next_method(123)
            .build(&mut assembly);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalid(details) => {
                assert!(details.contains("Kickoff method RID is required"));
            }
            _ => panic!("Expected ModificationInvalid error"),
        }
        Ok(())
    }

    #[test]
    fn test_statemachinemethod_builder_clone() {
        let builder = StateMachineMethodBuilder::new()
            .move_next_method(123)
            .kickoff_method(45);

        let cloned = builder.clone();
        assert_eq!(builder.move_next_method, cloned.move_next_method);
        assert_eq!(builder.kickoff_method, cloned.kickoff_method);
    }

    #[test]
    fn test_statemachinemethod_builder_debug() {
        let builder = StateMachineMethodBuilder::new()
            .move_next_method(123)
            .kickoff_method(45);

        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("StateMachineMethodBuilder"));
        assert!(debug_str.contains("move_next_method"));
        assert!(debug_str.contains("kickoff_method"));
    }

    #[test]
    fn test_statemachinemethod_builder_fluent_interface() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test method chaining
        let _change_ref = StateMachineMethodBuilder::new()
            .move_next_method(456)
            .kickoff_method(789)
            .build(&mut assembly)
            .expect("Should build successfully");

        Ok(())
    }

    #[test]
    fn test_statemachinemethod_builder_multiple_builds() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Build first mapping
        let ref1 = StateMachineMethodBuilder::new()
            .move_next_method(100)
            .kickoff_method(50)
            .build(&mut assembly)
            .expect("Should build first mapping");

        // Build second mapping
        let ref2 = StateMachineMethodBuilder::new()
            .move_next_method(200)
            .kickoff_method(60)
            .build(&mut assembly)
            .expect("Should build second mapping");

        // Verify change refs are different
        assert!(!Arc::ptr_eq(&ref1, &ref2));
        Ok(())
    }

    #[test]
    fn test_statemachinemethod_builder_large_method_ids() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test with large method RIDs
        let _change_ref = StateMachineMethodBuilder::new()
            .move_next_method(0xFFFF) // Large method RID
            .kickoff_method(0xFFFE) // Large method RID
            .build(&mut assembly)
            .expect("Should handle large method RIDs");

        Ok(())
    }
}

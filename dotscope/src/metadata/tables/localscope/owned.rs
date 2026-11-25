//! Owned `LocalScope` representation for resolved metadata access
//!
//! This module provides the [`LocalScope`] struct which represents fully resolved
//! `LocalScope` table data with convenient access methods for scope analysis and
//! debugging support.

use crate::metadata::{
    method::MethodRc,
    tables::{ImportScopeRc, LocalConstantList, LocalVariableList},
    token::Token,
};

/// Owned representation of a `LocalScope` table entry with resolved references
///
/// This structure provides a fully resolved view of local scope information,
/// containing all necessary data for scope analysis and debugging operations.
/// Unlike the raw representation, this struct contains resolved references to
/// actual objects rather than table indices.
///
/// # Scope Analysis
///
/// `LocalScope` entries define the ranges where local variables and constants
/// are visible within method IL code. Each scope has:
/// - Clear start and end boundaries (IL offsets)
/// - Associated variables and constants (fully resolved)
/// - Import context for namespace resolution
/// - Reference to containing method
///
/// # Reference Resolution
///
/// All table indices have been resolved to their actual objects:
/// - `method`: Strong reference to the containing `MethodDef`
/// - `import_scope`: Optional strong reference to `ImportScope`
/// - `variables`: Complete vector of `LocalVariable` entries
/// - `constants`: Complete vector of `LocalConstant` entries
#[derive(Clone)]
pub struct LocalScope {
    /// Row identifier (1-based index in the `LocalScope` table)
    pub rid: u32,

    /// Metadata token for this `LocalScope` entry (0x32000000 + rid)
    pub token: Token,

    /// Byte offset of this row in the original metadata stream
    pub offset: usize,

    /// Strong reference to the containing method
    ///
    /// References the method that contains this local scope.
    /// All local scopes must belong to a specific method.
    pub method: MethodRc,

    /// Optional strong reference to import scope for namespace context
    ///
    /// References the import scope that provides namespace context for
    /// this local scope. None if no specific import context applies.
    pub import_scope: Option<ImportScopeRc>,

    /// Resolved list of local variables in this scope
    ///
    /// Contains all local variables that belong to this scope.
    /// Empty list if this scope contains no variables.
    pub variables: LocalVariableList,

    /// Resolved list of local constants in this scope
    ///
    /// Contains all local constants that belong to this scope.
    /// Empty list if this scope contains no constants.
    pub constants: LocalConstantList,

    /// IL instruction offset where this scope begins
    ///
    /// Byte offset within the method's IL code where variables and
    /// constants in this scope become active and visible.
    pub start_offset: u32,

    /// Length of this scope in IL instruction bytes
    ///
    /// Number of IL bytes that this scope covers. The scope extends
    /// from `start_offset` to (`start_offset` + length - 1).
    pub length: u32,
}

impl LocalScope {
    /// Returns the IL offset where this scope ends
    ///
    /// Calculates the end offset as `start_offset` + length, representing
    /// the first IL offset that is no longer part of this scope.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::tables::LocalScope;
    /// # fn example(scope: &LocalScope) {
    /// println!("Scope covers IL offsets {} to {}",
    ///          scope.start_offset, scope.end_offset() - 1);
    /// # }
    /// ```
    #[must_use]
    pub fn end_offset(&self) -> u32 {
        self.start_offset.saturating_add(self.length)
    }

    /// Checks if this scope contains any local variables
    ///
    /// Returns true if the scope has at least one local variable defined.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use dotscope::metadata::tables::LocalScope;
    /// # fn example(scope: &LocalScope) {
    /// if scope.has_variables() {
    ///     println!("Scope has {} variables", scope.variables.count());
    /// }
    /// # }
    /// ```
    #[must_use]
    pub fn has_variables(&self) -> bool {
        !self.variables.is_empty()
    }

    /// Checks if this scope contains any local constants
    ///
    /// Returns true if the scope has at least one local constant defined.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use dotscope::metadata::tables::LocalScope;
    /// # fn example(scope: &LocalScope) {
    /// if scope.has_constants() {
    ///     println!("Scope has {} constants", scope.constants.count());
    /// }
    /// # }
    /// ```
    #[must_use]
    pub fn has_constants(&self) -> bool {
        !self.constants.is_empty()
    }

    /// Checks if this scope has an associated import scope
    ///
    /// Returns true if this scope has namespace import context
    /// defined through an associated import scope.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use dotscope::metadata::tables::LocalScope;
    /// # fn example(scope: &LocalScope) {
    /// if scope.has_import_scope() {
    ///     println!("Scope has import context");
    /// }
    /// # }
    /// ```
    #[must_use]
    pub fn has_import_scope(&self) -> bool {
        self.import_scope.is_some()
    }

    /// Checks if the given IL offset falls within this scope
    ///
    /// Returns true if the offset is within the range [`start_offset`, `end_offset`).
    /// The end offset is exclusive, following standard range conventions.
    ///
    /// # Arguments
    /// * `offset` - IL instruction offset to test
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::tables::LocalScope;
    /// # fn example(scope: &LocalScope) {
    /// let il_offset = 42;
    /// if scope.contains_offset(il_offset) {
    ///     println!("IL offset {} is within this scope", il_offset);
    /// }
    /// # }
    /// ```
    #[must_use]
    pub fn contains_offset(&self, offset: u32) -> bool {
        offset >= self.start_offset && offset < self.end_offset()
    }

    /// Returns the size of this scope in IL instruction bytes
    ///
    /// This is equivalent to the length field but provides a more
    /// descriptive method name for scope size queries.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::tables::LocalScope;
    /// # fn example(scope: &LocalScope) {
    /// println!("Scope covers {} bytes of IL code", scope.size());
    /// # }
    /// ```
    #[must_use]
    pub fn size(&self) -> u32 {
        self.length
    }
}

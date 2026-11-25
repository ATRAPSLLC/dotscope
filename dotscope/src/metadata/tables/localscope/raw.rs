//! Raw `LocalScope` table representation for Portable PDB format
//!
//! This module provides the [`LocalScopeRaw`] struct that represents
//! the binary format of `LocalScope` table entries as they appear in
//! the metadata tables stream. This is the low-level representation used during
//! the initial parsing phase, containing unresolved table indices.

use std::sync::Arc;

use crate::{
    metadata::{
        method::MethodMap,
        tables::{
            ImportScopeMap, LocalConstantMap, LocalScope, LocalScopeRc, LocalVariableMap,
            MemberRanges, TableId, TableInfoRef, TableRow,
        },
        token::Token,
    },
    Result,
};

/// Raw binary representation of a `LocalScope` table entry
///
/// This structure matches the exact binary layout of `LocalScope` table
/// entries in the metadata tables stream. All table references remain as unresolved
/// indices that must be resolved through the appropriate tables during the conversion
/// to the owned [`LocalScope`] variant.
///
/// # Binary Format
///
/// Each `LocalScope` table entry consists of:
/// - Method: Simple index into `MethodDef` table
/// - `ImportScope`: Simple index into `ImportScope` table
/// - `VariableList`: Simple index into `LocalVariable` table
/// - `ConstantList`: Simple index into `LocalConstant` table
/// - `StartOffset`: 4-byte unsigned integer (IL offset)
/// - `Length`: 4-byte unsigned integer (scope length in bytes)
#[derive(Debug, Clone)]
pub struct LocalScopeRaw {
    /// Row identifier (1-based index in the table)
    pub rid: u32,

    /// Metadata token for this `LocalScope` entry
    pub token: Token,

    /// Byte offset of this row in the original metadata stream
    pub offset: usize,

    /// Simple index into `MethodDef` table
    ///
    /// Identifies the method that contains this local scope. This is always
    /// a valid method reference as local scopes must belong to a method.
    pub method: u32,

    /// Simple index into `ImportScope` table
    ///
    /// References the import scope that provides the namespace context for
    /// this local scope. May be 0 if no specific import context is required.
    pub import_scope: u32,

    /// Simple index into `LocalVariable` table
    ///
    /// Points to the first local variable that belongs to this scope.
    /// Variables are stored consecutively, so this serves as a range start.
    /// May be 0 if this scope contains no variables.
    pub variable_list: u32,

    /// Simple index into `LocalConstant` table
    ///
    /// Points to the first local constant that belongs to this scope.
    /// Constants are stored consecutively, so this serves as a range start.
    /// May be 0 if this scope contains no constants.
    pub constant_list: u32,

    /// IL instruction offset where this scope begins
    ///
    /// Specifies the byte offset within the method's IL code where
    /// the variables and constants in this scope become active.
    pub start_offset: u32,

    /// Length of this scope in IL instruction bytes
    ///
    /// Specifies how many bytes of IL code this scope covers.
    /// The scope extends from `start_offset` to (`start_offset` + `length`).
    pub length: u32,
}

impl LocalScopeRaw {
    /// Converts this raw `LocalScope` entry to an owned [`LocalScope`] instance
    ///
    /// This method resolves the raw `LocalScope` entry to create a complete `LocalScope`
    /// object by resolving all table references and building the variable and constant lists
    /// using range determination based on the next scope's starting indices.
    ///
    /// # Parameters
    /// - `methods`: Map of resolved methods for method reference resolution
    /// - `import_scopes`: Map of resolved import scopes for import scope resolution
    /// - `variables_map`: Map of resolved local variables for building variable lists
    /// - `constants_map`: Map of resolved local constants for building constant lists
    /// - `variable_ranges`: The normalized `VariableList` runs of the whole `LocalScope` table
    ///   ([`TablesHeader::member_ranges`](crate::metadata::streams::TablesHeader::member_ranges)
    ///   with [`MemberList::LocalScopeVariables`](crate::metadata::tables::MemberList::LocalScopeVariables)),
    ///   clamped to the `LocalVariable` table so a hostile column cannot make a scope iterate
    ///   past it
    /// - `constant_ranges`: The normalized `ConstantList` runs
    ///   ([`MemberList::LocalScopeConstants`](crate::metadata::tables::MemberList::LocalScopeConstants))
    ///
    /// # Returns
    /// Returns `Ok(LocalScopeRc)` with the resolved scope data, or an error if
    /// any references are invalid or point to malformed data.
    ///
    /// # Errors
    /// Returns an error if the method or import scope reference is invalid. The variable and
    /// constant runs cannot fail: they are normalized to lie inside their tables, and a row in
    /// them that is not loaded is left out of the scope.
    pub fn to_owned(
        &self,
        methods: &MethodMap,
        import_scopes: &ImportScopeMap,
        variables_map: &LocalVariableMap,
        constants_map: &LocalConstantMap,
        variable_ranges: &MemberRanges,
        constant_ranges: &MemberRanges,
    ) -> Result<LocalScopeRc> {
        let method_token = Token::new(
            0x0600_0000_u32
                .checked_add(self.method)
                .ok_or_else(|| malformed_error!("Method token overflow: {}", self.method))?,
        );
        let method = methods
            .get(&method_token)
            .ok_or_else(|| malformed_error!("Invalid method index {} in LocalScope", self.method))?
            .value()
            .clone();

        let import_scope =
            if self.import_scope == 0 {
                None
            } else {
                let import_token =
                    Token::new(0x3500_0000_u32.checked_add(self.import_scope).ok_or_else(
                        || malformed_error!("ImportScope token overflow: {}", self.import_scope),
                    )?);
                Some(
                    import_scopes
                        .get(&import_token)
                        .ok_or_else(|| {
                            malformed_error!(
                                "Invalid import scope index {} in LocalScope",
                                self.import_scope
                            )
                        })?
                        .value()
                        .clone(),
                )
            };

        // A variable or constant that is not loaded is left out rather than failing the
        // scope: its own row failed (and was reported, or failed a strict load) before this
        // loader ran, and the scope's other locals are still worth having.
        let variables = Arc::new(boxcar::Vec::with_capacity(
            variable_ranges.range(self.rid).len(),
        ));
        for variable in variable_ranges
            .direct_members(self.rid, variables_map)
            .flatten()
        {
            _ = variables.push(variable);
        }

        let constants = Arc::new(boxcar::Vec::with_capacity(
            constant_ranges.range(self.rid).len(),
        ));
        for constant in constant_ranges
            .direct_members(self.rid, constants_map)
            .flatten()
        {
            _ = constants.push(constant);
        }

        let local_scope = LocalScope {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            method,
            import_scope,
            variables,
            constants,
            start_offset: self.start_offset,
            length: self.length,
        };

        Ok(Arc::new(local_scope))
    }
}

impl TableRow for LocalScopeRaw {
    /// Calculate the byte size of a LocalScope table row
    ///
    /// Returns the total size of one row in the LocalScope table, including:
    /// - method: 2 or 4 bytes (MethodDef table index)
    /// - import_scope: 2 or 4 bytes (ImportScope table index)
    /// - variable_list: 2 or 4 bytes (LocalVariable table index)
    /// - constant_list: 2 or 4 bytes (LocalConstant table index)
    /// - start_offset: 4 bytes
    /// - length: 4 bytes
    ///
    /// The index sizes depend on the metadata table requirements.
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* method */        sizes.table_index_bytes(TableId::MethodDef)
            /* import_scope */  .saturating_add(sizes.table_index_bytes(TableId::ImportScope))
            /* variable_list */ .saturating_add(sizes.table_index_bytes(TableId::LocalVariable))
            /* constant_list */ .saturating_add(sizes.table_index_bytes(TableId::LocalConstant))
            /* start_offset */  .saturating_add(4)
            /* length */        .saturating_add(4)

        )
    }
}

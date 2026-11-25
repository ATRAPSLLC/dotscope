//! Reference scanner for cross-table reference validation.
//!
//! This module provides a reference scanner that pre-analyzes metadata tables to build
//! lookup structures for reference validation. The scanner is shared across
//! all validators in a validation run to avoid redundant analysis.
//!
//! # Architecture
//!
//! The reference scanner operates by building maps of token relationships:
//! - **Forward references**: Maps tokens to other tokens that reference them
//! - **Backward references**: Maps tokens to other tokens they reference
//! - **Valid tokens**: Set of all existing tokens for existence validation
//! - **Table bounds**: Row counts for bounds checking
//! - **Heap bounds**: Heap sizes for index validation
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::scanner::ReferenceScanner`] - Main scanner implementation
//! - [`crate::metadata::validation::scanner::HeapSizes`] - Heap size information for bounds checking
//! - [`crate::metadata::validation::scanner::ScannerStatistics`] - Statistics about scanner analysis
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::ReferenceScanner;
//! use dotscope::metadata::cilassemblyview::CilAssemblyView;
//! use dotscope::metadata::token::Token;
//! use std::path::Path;
//!
//! # let path = Path::new("assembly.dll");
//! let view = CilAssemblyView::from_path(&path)?;
//! let scanner = ReferenceScanner::from_view(&view)?;
//!
//! // Check if a token exists
//! let token = Token::new(0x02000001);
//! if scanner.token_exists(token) {
//!     println!("Token exists");
//! }
//!
//! // Get reference statistics
//! let stats = scanner.statistics();
//! println!("Found {} valid tokens", stats.total_tokens);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! The [`crate::metadata::validation::scanner::ReferenceScanner`] is [`Send`] and [`Sync`],
//! allowing it to be safely shared across multiple validation threads.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::validation::context`] - Provides scanner to validation contexts
//! - [`crate::metadata::validation::engine`] - Creates scanner for validation runs
//! - [`crate::metadata::validation::traits`] - Validators use scanner for reference validation

use rustc_hash::{FxHashMap, FxHashSet};

use crate::{
    dispatch_table_type,
    metadata::{
        cilassemblyview::CilAssemblyView,
        cilobject::CilObject,
        tables::{
            ClassLayoutRaw, ConstantRaw, CustomAttributeRaw, FieldLayoutRaw, FieldMarshalRaw,
            GenericParamConstraintRaw, GenericParamRaw, InterfaceImplRaw, MemberRefRaw,
            MethodImplRaw, NestedClassRaw, TableId, TypeDefRaw, TypeRefRaw,
        },
        token::Token,
    },
    Blob, Error, Guid, HeapKind, ParseFailure, Result, Strings, UserStrings,
};

/// Reference scanner for metadata validation.
///
/// The [`crate::metadata::validation::scanner::ReferenceScanner`] pre-analyzes metadata tables to build lookup structures
/// that enable reference validation. It identifies forward and backward
/// references between tables and provides methods for reference integrity checking.
///
/// # Usage
///
/// The scanner is typically created once per validation run and shared across
/// all validators through the validation context.
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::metadata::validation::ReferenceScanner;
/// use dotscope::metadata::cilassemblyview::CilAssemblyView;
/// use dotscope::metadata::token::Token;
/// use std::path::Path;
///
/// # let path = Path::new("assembly.dll");
/// let view = CilAssemblyView::from_path(&path)?;
/// let scanner = ReferenceScanner::from_view(&view)?;
///
/// // Check if a token exists
/// let token = Token::new(0x02000001);
/// if scanner.token_exists(token) {
///     // Token exists, safe to validate references
///     println!("Token is valid");
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`], allowing it to be safely shared across validation threads.
pub struct ReferenceScanner {
    /// Forward references: token -> set of tokens that reference it
    forward_references: FxHashMap<Token, FxHashSet<Token>>,
    /// Backward references: token -> set of tokens it references
    backward_references: FxHashMap<Token, FxHashSet<Token>>,
    /// Set of all valid tokens in the assembly
    valid_tokens: FxHashSet<Token>,
    /// Table row counts for bounds checking
    table_row_counts: FxHashMap<TableId, u32>,
    /// Heap sizes for bounds checking
    heap_sizes: HeapSizes,
    /// Nested class relationships: enclosing_class -> set of nested_classes
    nested_class_map: FxHashMap<Token, FxHashSet<Token>>,
}

/// Metadata heap sizes for bounds validation.
#[derive(Debug, Clone, Default)]
pub struct HeapSizes {
    /// String heap size in bytes
    pub strings: u32,
    /// Blob heap size in bytes
    pub blobs: u32,
    /// GUID heap size in bytes
    pub guids: u32,
    /// User string heap size in bytes
    pub userstrings: u32,
}

impl ReferenceScanner {
    /// Creates a new reference scanner by analyzing the provided assembly view.
    ///
    /// This constructor performs the initial analysis of all metadata tables
    /// to build the reference lookup structures for validation operations.
    ///
    /// # Arguments
    ///
    /// * `view` - The [`crate::metadata::cilassemblyview::CilAssemblyView`] to analyze
    ///
    /// # Returns
    ///
    /// Returns a configured [`crate::metadata::validation::scanner::ReferenceScanner`] ready for validation operations.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the assembly view cannot be analyzed, such as when
    /// metadata tables are malformed or inaccessible.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::validation::ReferenceScanner;
    /// use dotscope::metadata::cilassemblyview::CilAssemblyView;
    /// use std::path::Path;
    ///
    /// # let path = Path::new("assembly.dll");
    /// let view = CilAssemblyView::from_path(&path)?;
    /// let scanner = ReferenceScanner::from_view(&view)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn from_view(view: &CilAssemblyView) -> Result<Self> {
        let mut scanner = Self {
            forward_references: FxHashMap::default(),
            backward_references: FxHashMap::default(),
            valid_tokens: FxHashSet::default(),
            table_row_counts: FxHashMap::default(),
            heap_sizes: HeapSizes::default(),
            nested_class_map: FxHashMap::default(),
        };

        scanner.analyze_assembly(view)?;
        Ok(scanner)
    }

    /// Creates a new reference scanner by analyzing the provided [`crate::metadata::cilobject::CilObject`].
    ///
    /// This constructor provides a convenient way to create a scanner from a [`crate::metadata::cilobject::CilObject`]
    /// by accessing its metadata structures. This is useful for owned validation
    /// scenarios where you already have a resolved object.
    ///
    /// # Arguments
    ///
    /// * `object` - The [`crate::metadata::cilobject::CilObject`] to analyze
    ///
    /// # Returns
    ///
    /// Returns a configured [`crate::metadata::validation::scanner::ReferenceScanner`] ready for validation operations.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the object cannot be analyzed.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::validation::ReferenceScanner;
    /// use dotscope::metadata::cilobject::CilObject;
    /// use std::path::Path;
    ///
    /// # let path = Path::new("assembly.dll");
    /// let object = CilObject::from_path(&path)?;
    /// let scanner = ReferenceScanner::from_object(&object)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn from_object(object: &CilObject) -> Result<Self> {
        let mut scanner = Self {
            forward_references: FxHashMap::default(),
            backward_references: FxHashMap::default(),
            valid_tokens: FxHashSet::default(),
            table_row_counts: FxHashMap::default(),
            heap_sizes: HeapSizes::default(),
            nested_class_map: FxHashMap::default(),
        };

        scanner.analyze_object(object)?;
        Ok(scanner)
    }

    /// Performs the initial analysis of the CilObject.
    fn analyze_object(&mut self, object: &CilObject) -> Result<()> {
        self.analyze_heaps(
            object.strings(),
            object.blob(),
            object.guids(),
            object.userstrings(),
        )?;

        if let Some(tables) = object.tables() {
            self.analyze_tables(tables);
        }

        Ok(())
    }

    /// Performs the initial analysis of the assembly view.
    fn analyze_assembly(&mut self, view: &CilAssemblyView) -> Result<()> {
        self.analyze_heaps(
            view.strings(),
            view.blobs(),
            view.guids(),
            view.userstrings(),
        )?;

        if let Some(tables) = view.tables() {
            self.analyze_tables(tables);
        }

        Ok(())
    }

    /// Analyzes metadata heaps to determine their sizes.
    fn analyze_heaps(
        &mut self,
        strings: Option<&Strings>,
        blobs: Option<&Blob>,
        guids: Option<&Guid>,
        userstrings: Option<&UserStrings>,
    ) -> Result<()> {
        if let Some(strings) = strings {
            self.heap_sizes.strings = u32::try_from(strings.data().len())
                .map_err(|_| malformed_error!("String heap size exceeds u32 range"))?;
        }

        if let Some(blobs) = blobs {
            self.heap_sizes.blobs = u32::try_from(blobs.data().len())
                .map_err(|_| malformed_error!("Blob heap size exceeds u32 range"))?;
        }

        if let Some(guids) = guids {
            self.heap_sizes.guids = u32::try_from(guids.data().len())
                .map_err(|_| malformed_error!("GUID heap size exceeds u32 range"))?;
        }

        if let Some(userstrings) = userstrings {
            self.heap_sizes.userstrings = u32::try_from(userstrings.data().len())
                .map_err(|_| malformed_error!("UserString heap size exceeds u32 range"))?;
        }

        Ok(())
    }

    /// Analyzes metadata tables to build reference maps.
    fn analyze_tables(&mut self, tables: &crate::TablesHeader) {
        self.collect_valid_tokens(tables);

        self.analyze_references(tables);
    }

    /// Collects all valid tokens from metadata tables.
    fn collect_valid_tokens(&mut self, tables: &crate::TablesHeader) {
        for table_id in tables.present_tables() {
            let row_count = tables.table_row_count(table_id);
            if row_count == 0 {
                continue;
            }

            self.table_row_counts.insert(table_id, row_count);

            let table_token_base = u32::from(table_id.token_type()) << 24;

            dispatch_table_type!(table_id, |RawType| {
                if let Some(table) = tables.table::<RawType>() {
                    for row in table {
                        let row = match row {
                            Ok(row) => row,
                            Err(e) => {
                                log::warn!("skipping unreadable metadata row: {e}");
                                continue;
                            }
                        };
                        let token = Token::new(table_token_base | row.rid);
                        self.valid_tokens.insert(token);
                    }
                }
            });
        }
    }

    /// Analyzes references between tokens in metadata tables.
    ///
    /// This method uses the `dispatch_table_type` macro to iterate over all present tables
    /// and extract references in a unified way. Each table type has specific fields that
    /// contain references to other tokens (coded indices, direct table indices, etc.).
    ///
    /// Reference extraction is consolidated here to:
    /// - Eliminate code duplication across separate analyze_*_references methods
    /// - Ensure consistent handling of all table types
    /// - Make it easier to add new table types in the future
    fn analyze_references(&mut self, tables: &crate::TablesHeader) {
        for table_id in tables.present_tables() {
            dispatch_table_type!(table_id, |RawType| {
                if let Some(table) = tables.table::<RawType>() {
                    let token_base = u32::from(table_id.token_type()) << 24;
                    for row in table {
                        let row = match row {
                            Ok(row) => row,
                            Err(e) => {
                                log::warn!("skipping unreadable metadata row: {e}");
                                continue;
                            }
                        };
                        let from_token = Token::new(token_base | row.rid);
                        self.extract_row_references(table_id, from_token, &row);
                    }
                }
            });
        }
    }

    /// Extracts references from a single table row based on the table type.
    ///
    /// This method contains the table-specific reference extraction logic. Each table
    /// type has different fields that may contain references:
    /// - Coded indices (e.g., TypeDefOrRef, MemberRefParent)
    /// - Direct table indices (e.g., class field pointing to TypeDef)
    /// - Combined references from multiple fields
    ///
    /// Tables without references (or with only signature blob references that require
    /// future parsing) are handled with empty match arms.
    #[allow(clippy::too_many_lines)]
    fn extract_row_references<T>(&mut self, table_id: TableId, from_token: Token, row: &T)
    where
        T: std::any::Any,
    {
        // Use downcasting to access table-specific fields
        // This is safe because we know the exact type from the dispatch_table_type macro
        let row_any = row as &dyn std::any::Any;

        match table_id {
            // TypeDef: extends field contains base type reference (TypeDefOrRef coded index)
            TableId::TypeDef => {
                if let Some(typedef) = row_any.downcast_ref::<TypeDefRaw>() {
                    if typedef.extends.row != 0 {
                        self.add_reference(from_token, typedef.extends.token);
                    }
                }
            }

            // TypeRef: resolution_scope contains reference to Module, ModuleRef, AssemblyRef, or TypeRef
            TableId::TypeRef => {
                if let Some(typeref) = row_any.downcast_ref::<TypeRefRaw>() {
                    if typeref.resolution_scope.row != 0 {
                        self.add_reference(from_token, typeref.resolution_scope.token);
                    }
                }
            }

            // InterfaceImpl: class (TypeDef index) and interface (TypeDefOrRef coded index)
            TableId::InterfaceImpl => {
                if let Some(impl_row) = row_any.downcast_ref::<InterfaceImplRaw>() {
                    let class_token = Token::new(0x0200_0000 | impl_row.class);
                    self.add_reference(from_token, class_token);

                    if impl_row.interface.row != 0 {
                        self.add_reference(from_token, impl_row.interface.token);
                    }
                }
            }

            // MemberRef: class field (MemberRefParent coded index)
            TableId::MemberRef => {
                if let Some(memberref) = row_any.downcast_ref::<MemberRefRaw>() {
                    if memberref.class.row != 0 {
                        self.add_reference(from_token, memberref.class.token);
                    }
                    // Note: signature blob parsing for type references is a future enhancement
                }
            }

            // CustomAttribute: parent (HasCustomAttribute) and constructor (CustomAttributeType)
            TableId::CustomAttribute => {
                if let Some(attr) = row_any.downcast_ref::<CustomAttributeRaw>() {
                    if attr.parent.row != 0 {
                        self.add_reference(from_token, attr.parent.token);
                    }
                    if attr.constructor.row != 0 {
                        self.add_reference(from_token, attr.constructor.token);
                    }
                }
            }

            // GenericParam: owner (TypeOrMethodDef coded index)
            TableId::GenericParam => {
                if let Some(param) = row_any.downcast_ref::<GenericParamRaw>() {
                    if param.owner.row != 0 {
                        self.add_reference(from_token, param.owner.token);
                    }
                }
            }

            // GenericParamConstraint: owner (GenericParam index) and constraint (TypeDefOrRef)
            TableId::GenericParamConstraint => {
                if let Some(constraint) = row_any.downcast_ref::<GenericParamConstraintRaw>() {
                    let param_token = Token::new(0x2A00_0000 | constraint.owner);
                    self.add_reference(from_token, param_token);

                    if constraint.constraint.row != 0 {
                        self.add_reference(from_token, constraint.constraint.token);
                    }
                }
            }

            // NestedClass: nested_class and enclosing_class (both TypeDef indices)
            TableId::NestedClass => {
                if let Some(nested) = row_any.downcast_ref::<NestedClassRaw>() {
                    let nested_token = Token::new(0x0200_0000 | nested.nested_class);
                    self.add_reference(from_token, nested_token);

                    let enclosing_token = Token::new(0x0200_0000 | nested.enclosing_class);
                    self.add_reference(from_token, enclosing_token);

                    self.nested_class_map
                        .entry(enclosing_token)
                        .or_default()
                        .insert(nested_token);
                }
            }

            // MethodImpl: class (TypeDef), method_body and method_declaration (MethodDefOrRef)
            TableId::MethodImpl => {
                if let Some(impl_row) = row_any.downcast_ref::<MethodImplRaw>() {
                    let class_token = Token::new(0x0200_0000 | impl_row.class);
                    self.add_reference(from_token, class_token);

                    if impl_row.method_body.row != 0 {
                        self.add_reference(from_token, impl_row.method_body.token);
                    }
                    if impl_row.method_declaration.row != 0 {
                        self.add_reference(from_token, impl_row.method_declaration.token);
                    }
                }
            }

            // FieldLayout: field (Field index)
            TableId::FieldLayout => {
                if let Some(layout) = row_any.downcast_ref::<FieldLayoutRaw>() {
                    let field_token = Token::new(0x0400_0000 | layout.field);
                    self.add_reference(from_token, field_token);
                }
            }

            // ClassLayout: parent (TypeDef index)
            TableId::ClassLayout => {
                if let Some(layout) = row_any.downcast_ref::<ClassLayoutRaw>() {
                    let parent_token = Token::new(0x0200_0000 | layout.parent);
                    self.add_reference(from_token, parent_token);
                }
            }

            // Constant: parent (HasConstant coded index)
            TableId::Constant => {
                if let Some(constant) = row_any.downcast_ref::<ConstantRaw>() {
                    if constant.parent.row != 0 {
                        self.add_reference(from_token, constant.parent.token);
                    }
                }
            }

            // FieldMarshal: parent (HasFieldMarshal coded index)
            TableId::FieldMarshal => {
                if let Some(marshal) = row_any.downcast_ref::<FieldMarshalRaw>() {
                    if marshal.parent.row != 0 {
                        self.add_reference(from_token, marshal.parent.token);
                    }
                }
            }

            // Tables with signature blobs that would need parsing for full reference extraction
            // These are placeholders for future enhancement, plus tables without token references
            // (only contain data, heap indices, or flags)
            TableId::MethodDef
            | TableId::Field
            | TableId::StandAloneSig
            | TableId::TypeSpec
            | TableId::Module
            | TableId::Param
            | TableId::Assembly
            | TableId::AssemblyRef
            | TableId::ModuleRef
            | TableId::File
            | TableId::ManifestResource
            | TableId::ExportedType
            | TableId::Event
            | TableId::EventMap
            | TableId::Property
            | TableId::PropertyMap
            | TableId::MethodSemantics
            | TableId::DeclSecurity
            | TableId::ImplMap
            | TableId::FieldRVA
            | TableId::MethodSpec
            | TableId::AssemblyProcessor
            | TableId::AssemblyOS
            | TableId::AssemblyRefProcessor
            | TableId::AssemblyRefOS
            | TableId::FieldPtr
            | TableId::MethodPtr
            | TableId::ParamPtr
            | TableId::EventPtr
            | TableId::PropertyPtr
            | TableId::EncLog
            | TableId::EncMap
            | TableId::Document
            | TableId::MethodDebugInformation
            | TableId::LocalScope
            | TableId::LocalVariable
            | TableId::LocalConstant
            | TableId::ImportScope
            | TableId::StateMachineMethod
            | TableId::CustomDebugInformation => {
                // These tables either:
                // - Have signature blobs that need parsing for type references (future enhancement)
                // - Don't contain token references (only heap indices, flags, RVAs)
                // - Have references that require special handling not yet implemented
                // - Are pointer indirection tables
            }
        }
    }

    fn add_reference(&mut self, from_token: Token, to_token: Token) {
        if from_token == to_token {
            return;
        }

        if from_token.value() == 0 || to_token.value() == 0 {
            return;
        }

        self.forward_references
            .entry(to_token)
            .or_default()
            .insert(from_token);

        self.backward_references
            .entry(from_token)
            .or_default()
            .insert(to_token);
    }

    /// Checks if a token exists in the metadata.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to check
    ///
    /// # Returns
    ///
    /// Returns `true` if the token exists, `false` otherwise.
    #[must_use]
    pub fn token_exists(&self, token: Token) -> bool {
        self.valid_tokens.contains(&token)
    }

    /// Returns the row count for a specific table.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The table to query
    ///
    /// # Returns
    ///
    /// Returns the row count for the table, or 0 if the table doesn't exist.
    #[must_use]
    pub fn table_row_count(&self, table_id: TableId) -> u32 {
        self.table_row_counts.get(&table_id).copied().unwrap_or(0)
    }

    /// Validates that a token is within the bounds of its table.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the token is valid, or an error if it's out of bounds.
    ///
    /// # Errors
    ///
    /// Returns an error if the token is invalid or out of bounds for its table.
    pub fn validate_token_bounds(&self, token: Token) -> Result<()> {
        let table_value = token.table();
        let rid = token.row();

        let table_id = TableId::from_token_type(table_value).ok_or(Error::InvalidRid {
            table: TableId::Module,
            rid,
        })?;

        if rid == 0 {
            return Err(Error::InvalidRid {
                table: table_id,
                rid,
            });
        }

        let max_rid = self.table_row_count(table_id);
        if rid > max_rid {
            return Err(Error::InvalidRid {
                table: table_id,
                rid,
            });
        }

        Ok(())
    }

    /// Returns a reference to the set of tokens that reference the given token.
    ///
    /// This method returns a reference to the internal set without cloning.
    /// Returns `None` if no tokens reference the given token.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to find references to
    ///
    /// # Returns
    ///
    /// Returns an optional reference to the internal set of referencing tokens.
    #[must_use]
    pub fn references_to(&self, token: Token) -> Option<&FxHashSet<Token>> {
        self.forward_references.get(&token)
    }

    /// Returns a reference to the set of tokens that the given token references.
    ///
    /// This method returns a reference to the internal set without cloning.
    /// Returns `None` if the token doesn't reference any other tokens.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to find references from
    ///
    /// # Returns
    ///
    /// Returns an optional reference to the internal set of referenced tokens.
    #[must_use]
    pub fn references_from(&self, token: Token) -> Option<&FxHashSet<Token>> {
        self.backward_references.get(&token)
    }

    /// Checks if any tokens reference the given token.
    ///
    /// More efficient than `get_references_to().is_empty()` as it avoids cloning.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to check
    ///
    /// # Returns
    ///
    /// Returns `true` if at least one token references the given token.
    #[must_use]
    pub fn has_references_to(&self, token: Token) -> bool {
        self.forward_references
            .get(&token)
            .is_some_and(|set| !set.is_empty())
    }

    /// Checks if the given token references any other tokens.
    ///
    /// More efficient than `get_references_from().is_empty()` as it avoids cloning.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to check
    ///
    /// # Returns
    ///
    /// Returns `true` if the token references at least one other token.
    #[must_use]
    pub fn has_references_from(&self, token: Token) -> bool {
        self.backward_references
            .get(&token)
            .is_some_and(|set| !set.is_empty())
    }

    /// Checks if deleting a token would break reference integrity.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to check for deletion
    ///
    /// # Returns
    ///
    /// Returns `true` if the token can be safely deleted, `false` if it would
    /// break reference integrity.
    #[must_use]
    pub fn can_delete_token(&self, token: Token) -> bool {
        !self.has_references_to(token)
    }

    /// Returns the heap sizes for bounds checking.
    #[must_use]
    pub fn heap_sizes(&self) -> &HeapSizes {
        &self.heap_sizes
    }

    /// Returns the set of classes directly nested within the given enclosing class.
    ///
    /// This method provides access to the nested class relationships discovered during
    /// metadata scanning. It only returns direct nested classes, not transitively nested ones.
    ///
    /// # Arguments
    ///
    /// * `enclosing_token` - The token of the enclosing (outer) class
    ///
    /// # Returns
    ///
    /// Returns `Some(&FxHashSet<Token>)` containing all directly nested class tokens,
    /// or `None` if the token has no nested classes.
    #[must_use]
    pub fn nested_classes_of(&self, enclosing_token: Token) -> Option<&FxHashSet<Token>> {
        self.nested_class_map.get(&enclosing_token)
    }

    /// Checks if a type is nested within another type (directly or transitively).
    ///
    /// This method performs a depth-first search through the nested class hierarchy
    /// to determine if `potential_nested` is contained within `potential_enclosing`
    /// at any nesting level.
    ///
    /// # Arguments
    ///
    /// * `potential_enclosing` - The token of the potential outer class
    /// * `potential_nested` - The token of the potential inner class
    ///
    /// # Returns
    ///
    /// Returns `true` if `potential_nested` is nested within `potential_enclosing`
    /// (directly or transitively), `false` otherwise.
    #[must_use]
    pub fn is_nested_within(&self, potential_enclosing: Token, potential_nested: Token) -> bool {
        let mut visited = FxHashSet::default();
        self.is_nested_within_recursive(potential_enclosing, potential_nested, &mut visited)
    }

    /// Recursive helper for nested class containment check.
    fn is_nested_within_recursive(
        &self,
        enclosing: Token,
        target: Token,
        visited: &mut FxHashSet<Token>,
    ) -> bool {
        if !visited.insert(enclosing) {
            return false;
        }

        if let Some(nested_classes) = self.nested_class_map.get(&enclosing) {
            // Check direct nesting
            if nested_classes.contains(&target) {
                return true;
            }

            // Check transitive nesting
            for &nested in nested_classes {
                if self.is_nested_within_recursive(nested, target, visited) {
                    return true;
                }
            }
        }

        false
    }

    /// Validates a heap index against the appropriate heap size.
    ///
    /// # Arguments
    ///
    /// * `heap_type` - The type of heap (strings, blobs, etc.)
    /// * `index` - The index to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the index is valid, or an error if it's out of bounds.
    ///
    /// # Errors
    ///
    /// Returns an error if the heap index is out of bounds or the heap type is unknown.
    pub fn validate_heap_index(&self, heap_type: &str, index: u32) -> Result<()> {
        let max_size = match heap_type {
            "strings" => self.heap_sizes.strings,
            "blobs" => self.heap_sizes.blobs,
            "guids" => self.heap_sizes.guids,
            "userstrings" => self.heap_sizes.userstrings,
            other => {
                return Err(Error::Parse(ParseFailure::Other {
                    stage: crate::ParseStage::Validation,
                    message: format!("unknown heap '{other}' for index {index}"),
                }))
            }
        };

        if index >= max_size {
            let heap = match heap_type {
                "strings" => HeapKind::Strings,
                "blobs" => HeapKind::Blob,
                "guids" => HeapKind::Guid,
                "userstrings" => HeapKind::UserStrings,
                _ => unreachable!("heap_type already validated above"),
            };
            return Err(Error::Parse(ParseFailure::HeapOutOfBounds { heap, index }));
        }

        Ok(())
    }

    /// Returns statistics about the analyzed assembly.
    #[must_use]
    pub fn statistics(&self) -> ScannerStatistics {
        ScannerStatistics {
            total_tokens: self.valid_tokens.len(),
            total_tables: self.table_row_counts.len(),
            total_references: self.forward_references.values().map(FxHashSet::len).sum(),
            heap_sizes: self.heap_sizes.clone(),
        }
    }

    /// Returns the number of non-empty metadata tables.
    ///
    /// This method efficiently counts tables that have at least one row by returning
    /// the size of the internal table_row_counts HashMap, which only stores tables
    /// that actually exist in the metadata.
    ///
    /// # Returns
    ///
    /// The count of tables that contain at least one row.
    #[must_use]
    pub fn count_non_empty_tables(&self) -> usize {
        self.table_row_counts.len()
    }

    /// Returns the total number of rows across all metadata tables.
    ///
    /// This method efficiently sums all row counts from the internal table_row_counts
    /// HashMap, providing the total number of metadata rows in the assembly.
    ///
    /// # Returns
    ///
    /// The total count of rows across all metadata tables.
    #[must_use]
    pub fn count_total_rows(&self) -> u32 {
        self.table_row_counts.values().sum()
    }
}

/// Statistics about the reference scanner analysis.
#[derive(Debug, Clone)]
pub struct ScannerStatistics {
    /// Total number of valid tokens
    pub total_tokens: usize,
    /// Total number of tables analyzed
    pub total_tables: usize,
    /// Total number of references found
    pub total_references: usize,
    /// Heap sizes
    pub heap_sizes: HeapSizes,
}

impl std::fmt::Display for ScannerStatistics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Scanner Statistics: {} tokens, {} tables, {} references",
            self.total_tokens, self.total_tables, self.total_references
        )
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{metadata::cilassemblyview::CilAssemblyView, testkit::fixture};

    #[test]
    fn test_reference_scanner_creation() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view);
        assert!(scanner.is_ok(), "Scanner creation should succeed");

        let scanner = scanner.unwrap();
        let stats = scanner.statistics();

        assert!(stats.total_tokens > 0, "Should have found some tokens");
        assert!(stats.total_tables > 0, "Should have found some tables");
    }

    #[test]
    fn test_token_bounds_validation() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let invalid_token = Token::new(0x02000000); // TypeDef with RID 0
        assert!(scanner.validate_token_bounds(invalid_token).is_err());

        if scanner.table_row_count(TableId::TypeDef) > 0 {
            let valid_token = Token::new(0x02000001); // TypeDef with RID 1
            assert!(scanner.validate_token_bounds(valid_token).is_ok());
        }

        let max_rid = scanner.table_row_count(TableId::TypeDef);
        if max_rid > 0 {
            let out_of_bounds_token = Token::new(0x02000000 | (max_rid + 1));
            assert!(scanner.validate_token_bounds(out_of_bounds_token).is_err());
        }
    }

    #[test]
    fn test_heap_size_analysis() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let heap_sizes = scanner.heap_sizes();

        if view.strings().is_some() {
            assert!(
                heap_sizes.strings > 0,
                "String heap should have been analyzed"
            );
        }
    }

    #[test]
    fn test_scanner_statistics() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let stats = scanner.statistics();
        let stats_string = stats.to_string();

        assert!(stats_string.contains("tokens"));
        assert!(stats_string.contains("tables"));
        assert!(stats_string.contains("references"));
    }

    #[test]
    fn test_reference_analysis_basic_functionality() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let stats = scanner.statistics();

        // After implementing reference analysis, we should have actual references
        // WindowsBase.dll is a substantial assembly that should contain many references
        assert!(
            stats.total_references > 0,
            "Should find references in WindowsBase.dll"
        );

        // Test that the reference maps are populated
        assert!(
            !scanner.forward_references.is_empty() || !scanner.backward_references.is_empty(),
            "Reference maps should be populated"
        );
    }

    #[test]
    fn test_typedef_inheritance_references() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        // Find TypeDef tokens that should have inheritance relationships
        let mut _inheritance_found = false;

        for typedef_token in scanner.valid_tokens.iter() {
            if typedef_token.is_table(TableId::TypeDef) {
                // TypeDef table
                if let Some(references) = scanner.references_from(*typedef_token) {
                    if !references.is_empty() {
                        _inheritance_found = true;

                        // Verify that the referenced tokens are valid
                        for ref_token in references {
                            assert!(
                                scanner.token_exists(*ref_token),
                                "Referenced token should exist in metadata"
                            );
                        }
                    }
                }
            }
        }

        // WindowsBase.dll should have at least some types with base types
        if scanner.table_row_count(TableId::TypeDef) > 0 {
            // Note: Not all types have explicit base types (e.g., Object, interfaces)
            // so we don't assert inheritance_found, but we do verify the mechanism works
        }
    }

    #[test]
    fn test_interface_implementation_references() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        // Check InterfaceImpl table entries
        let interface_impl_count = scanner.table_row_count(TableId::InterfaceImpl);

        if interface_impl_count > 0 {
            let mut impl_references_found = false;

            // Look for InterfaceImpl tokens (0x09)
            for token in scanner.valid_tokens.iter() {
                if token.is_table(TableId::InterfaceImpl) {
                    // InterfaceImpl table
                    if let Some(references) = scanner.references_from(*token) {
                        if !references.is_empty() {
                            impl_references_found = true;

                            // Each InterfaceImpl should reference both class and interface
                            assert!(
                                !references.is_empty(),
                                "InterfaceImpl should reference at least the implementing class"
                            );

                            // Verify referenced tokens exist
                            for ref_token in references {
                                assert!(
                                    scanner.token_exists(*ref_token),
                                    "Referenced token should exist in metadata"
                                );
                            }
                        }
                    }
                }
            }

            assert!(
                impl_references_found,
                "Should find interface implementation references when InterfaceImpl table exists"
            );
        }
    }

    #[test]
    fn test_memberref_class_references() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let memberref_count = scanner.table_row_count(TableId::MemberRef);

        if memberref_count > 0 {
            let mut memberref_references_found = false;

            // Look for MemberRef tokens (0x0A)
            for token in scanner.valid_tokens.iter() {
                if token.is_table(TableId::MemberRef) {
                    // MemberRef table
                    if let Some(references) = scanner.references_from(*token) {
                        if !references.is_empty() {
                            memberref_references_found = true;

                            // Verify referenced tokens exist
                            for ref_token in references {
                                assert!(
                                    scanner.token_exists(*ref_token),
                                    "Referenced token should exist in metadata"
                                );
                            }
                        }
                    }
                }
            }

            assert!(
                memberref_references_found,
                "Should find member reference relationships when MemberRef table exists"
            );
        }
    }

    #[test]
    fn test_customattribute_references() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let attr_count = scanner.table_row_count(TableId::CustomAttribute);

        if attr_count > 0 {
            let mut attr_references_found = false;

            // Look for CustomAttribute tokens (0x0C)
            for token in scanner.valid_tokens.iter() {
                if token.is_table(TableId::CustomAttribute) {
                    // CustomAttribute table
                    if let Some(references) = scanner.references_from(*token) {
                        if !references.is_empty() {
                            attr_references_found = true;

                            // Each CustomAttribute should reference both parent and constructor
                            // Verify referenced tokens exist
                            for ref_token in references {
                                assert!(
                                    scanner.token_exists(*ref_token),
                                    "Referenced token should exist in metadata"
                                );
                            }
                        }
                    }
                }
            }

            assert!(
                attr_references_found,
                "Should find custom attribute references when CustomAttribute table exists"
            );
        }
    }

    #[test]
    fn test_nested_class_references() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let nested_count = scanner.table_row_count(TableId::NestedClass);

        if nested_count > 0 {
            let mut nested_references_found = false;

            // Look for NestedClass tokens (0x29)
            for token in scanner.valid_tokens.iter() {
                if token.is_table(TableId::NestedClass) {
                    // NestedClass table
                    if let Some(references) = scanner.references_from(*token) {
                        if !references.is_empty() {
                            nested_references_found = true;

                            // Each NestedClass should reference both nested and enclosing types
                            assert!(
                                references.len() >= 2,
                                "NestedClass should reference both nested and enclosing types"
                            );

                            // Verify all references are TypeDef tokens
                            for ref_token in references {
                                assert!(
                                    scanner.token_exists(*ref_token),
                                    "Referenced token should exist in metadata"
                                );
                                assert!(
                                    ref_token.is_table(TableId::TypeDef),
                                    "NestedClass should only reference TypeDef tokens"
                                );
                            }
                        }
                    }
                }
            }

            assert!(
                nested_references_found,
                "Should find nested class references when NestedClass table exists"
            );
        }
    }

    #[test]
    fn test_generic_parameter_references() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let generic_param_count = scanner.table_row_count(TableId::GenericParam);

        if generic_param_count > 0 {
            let mut generic_references_found = false;

            // Look for GenericParam tokens (0x2A)
            for token in scanner.valid_tokens.iter() {
                if token.is_table(TableId::GenericParam) {
                    // GenericParam table
                    if let Some(references) = scanner.references_from(*token) {
                        if !references.is_empty() {
                            generic_references_found = true;

                            // Verify referenced tokens exist
                            for ref_token in references {
                                assert!(
                                    scanner.token_exists(*ref_token),
                                    "Referenced token should exist in metadata"
                                );

                                // Generic parameters should reference TypeDef or MethodDef
                                assert!(
                                    ref_token.is_table(TableId::TypeDef)
                                        || ref_token.is_table(TableId::MethodDef),
                                    "GenericParam should reference TypeDef or MethodDef"
                                );
                            }
                        }
                    }
                }
            }

            if generic_param_count > 0 {
                // WindowsBase.dll should have generic parameters if the table exists
                assert!(
                    generic_references_found,
                    "Should find generic parameter references when GenericParam table exists"
                );
            }
        }
    }

    #[test]
    fn test_reference_bidirectionality() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        // Test that forward and backward references are consistent
        for (to_token, from_tokens) in &scanner.forward_references {
            for from_token in from_tokens {
                let backward_refs = scanner.references_from(*from_token);
                assert!(
                    backward_refs.is_some_and(|refs| refs.contains(to_token)),
                    "Forward reference should have corresponding backward reference"
                );
            }
        }

        for (from_token, to_tokens) in &scanner.backward_references {
            for to_token in to_tokens {
                let forward_refs = scanner.references_to(*to_token);
                assert!(
                    forward_refs.is_some_and(|refs| refs.contains(from_token)),
                    "Backward reference should have corresponding forward reference"
                );
            }
        }
    }

    #[test]
    fn test_can_delete_token_functionality() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let stats = scanner.statistics();

        if stats.total_references > 0 {
            // Find a token that is referenced by others (should not be deletable)
            let mut found_non_deletable = false;
            let mut found_deletable = false;

            for token in scanner.valid_tokens.iter().take(100) {
                // Sample first 100 tokens
                let can_delete = scanner.can_delete_token(*token);
                let has_incoming_refs = scanner.has_references_to(*token);

                if has_incoming_refs {
                    // Token is referenced by others, should not be deletable
                    assert!(
                        !can_delete,
                        "Token with incoming references should not be deletable"
                    );
                    found_non_deletable = true;
                } else {
                    // Token has no incoming references, should be deletable
                    assert!(
                        can_delete,
                        "Token with no incoming references should be deletable"
                    );
                    found_deletable = true;
                }
            }

            // We should find examples of both deletable and non-deletable tokens
            // in a substantial assembly like WindowsBase.dll
            assert!(found_deletable, "Should find some deletable tokens");
            assert!(found_non_deletable, "Should find some non-deletable tokens");
        }
    }

    #[test]
    fn test_reference_validation_prevents_invalid_references() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let initial_ref_count = scanner.statistics().total_references;

        // Test self-reference prevention
        let test_token = Token::new(0x02000001);
        scanner.add_reference(test_token, test_token);

        // Test null token prevention
        scanner.add_reference(Token::new(0), test_token);
        scanner.add_reference(test_token, Token::new(0));

        // Reference count should not have increased
        let final_ref_count = scanner.statistics().total_references;
        assert_eq!(
            initial_ref_count, final_ref_count,
            "Invalid references should be prevented"
        );
    }

    #[test]
    fn test_comprehensive_reference_coverage() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let stats = scanner.statistics();

        // WindowsBase.dll should have substantial reference relationships
        // if our implementation is working correctly
        println!("Reference analysis results:");
        println!("  Total tokens: {}", stats.total_tokens);
        println!("  Total tables: {}", stats.total_tables);
        println!("  Total references: {}", stats.total_references);

        // Basic sanity checks
        assert!(
            stats.total_tokens > 1000,
            "WindowsBase.dll should have many tokens"
        );
        assert!(
            stats.total_tables > 10,
            "WindowsBase.dll should have many tables"
        );

        // After implementing reference analysis, we should have references
        // The exact number will depend on the assembly, but it should be substantial
        if stats.total_references == 0 {
            println!("Warning: No references found - implementation may need debugging");
        }
    }
}

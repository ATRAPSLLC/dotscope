//! Builder for constructing `ImportScope` table entries
//!
//! This module provides the [`crate::metadata::tables::importscope::ImportScopeBuilder`] which enables fluent construction
//! of `ImportScope` metadata table entries. The builder follows the established
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
//! let imports_bytes = vec![0x01, 0x02]; // Raw import data
//!
//! let scope_token = ImportScopeBuilder::new()
//!     .parent(0)                     // Root scope (no parent)
//!     .imports(&imports_bytes)       // Raw import blob data
//!     .build(&mut assembly)?;
//! # Ok::<(), dotscope::Error>(())
//! ```

use crate::{
    cilassembly::{BlobComposite, ChangeRefRc, CilAssembly, CompositeImport},
    metadata::{
        importscope::{ImportDeclaration, ImportKind, ImportsInfo},
        tables::{ImportScopeRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for constructing `ImportScope` table entries
///
/// Provides a fluent interface for building `ImportScope` metadata table entries.
/// The builder validates all required fields are provided and handles proper
/// integration with the metadata system.
///
/// # Required Fields
/// - `parent`: Parent scope index (0 for root scope, must be explicitly set)
/// - the imports: either their declarations ([`declarations`](Self::declarations)), whose
///   aliases and namespaces the builder adds as blobs, or a raw imports blob
///   ([`imports`](Self::imports)) naming blobs already in the heap
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
/// # let mut assembly = CilAssembly::new(view);
/// // Root import scope
/// let imports_data = vec![0x01, 0x02, 0x03]; // Raw import blob
/// let root_scope = ImportScopeBuilder::new()
///     .parent(0)  // Root scope
///     .imports(&imports_data)
///     .build(&mut assembly)?;
///
/// // Child import scope
/// let child_scope = ImportScopeBuilder::new()
///     .parent(1)  // References first scope
///     .imports(&imports_data)
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct ImportScopeBuilder {
    /// Parent scope index (0 for root scope)
    parent: Option<u32>,
    /// Raw import blob data
    imports: Option<Vec<u8>>,
    /// The import declarations, encoded when the assembly is written
    declarations: Option<ImportsInfo>,
}

impl ImportScopeBuilder {
    /// Creates a new `ImportScopeBuilder` with default values
    ///
    /// Initializes a new builder instance with all fields unset. The caller
    /// must provide the required fields (parent and imports) before calling build().
    ///
    /// # Returns
    /// A new `ImportScopeBuilder` instance ready for configuration
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = ImportScopeBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            parent: None,
            imports: None,
            declarations: None,
        }
    }

    /// Sets the parent scope index
    ///
    /// Specifies the parent import scope that encloses this scope. Use 0 for
    /// root-level import scopes that have no parent.
    ///
    /// # Parameters
    /// - `parent`: The parent scope index (0 for root scope)
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// // Root scope
    /// let builder = ImportScopeBuilder::new()
    ///     .parent(0);
    ///
    /// // Child scope referencing parent
    /// let child_builder = ImportScopeBuilder::new()
    ///     .parent(1);  // References scope with RID 1
    /// ```
    #[must_use]
    pub fn parent(mut self, parent: u32) -> Self {
        self.parent = Some(parent);
        self
    }

    /// Sets the import blob data
    ///
    /// Specifies the raw import blob data for this scope. These bytes
    /// represent the import information as defined in the Portable PDB format: each
    /// declaration's kind followed by its fields, the aliases and namespaces as `#Blob`
    /// offsets of the input heap and the assemblies as AssemblyRef rows. The writer renumbers
    /// those offsets and rows when the heap is rebuilt or rows move. To import text the heap
    /// does not hold yet, use [`declarations`](Self::declarations). Setting the blob replaces
    /// any declarations set before.
    ///
    /// # Parameters
    /// - `imports`: The raw import blob data
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// // ImportNamespace (1) of the namespace at blob offset 0x10 of the input heap
    /// let import_data = vec![0x01, 0x10];
    /// let builder = ImportScopeBuilder::new()
    ///     .imports(&import_data);
    ///
    /// // Empty import scope
    /// let empty_builder = ImportScopeBuilder::new()
    ///     .imports(&[]);
    /// ```
    #[must_use]
    pub fn imports(mut self, imports: &[u8]) -> Self {
        self.imports = Some(imports.to_vec());
        self.declarations = None;
        self
    }

    /// Sets the import declarations
    ///
    /// Each declaration's alias and namespace are added to the `#Blob` heap as UTF-8 text
    /// (an empty one is blob index 0), and the imports blob is encoded with their offsets
    /// when the assembly is written. Assemblies are AssemblyRef tokens and types TypeDef,
    /// TypeRef or TypeSpec tokens, of the input or of rows a change adds. Setting the
    /// declarations replaces any raw blob set before.
    ///
    /// # Parameters
    /// - `declarations`: The scope's imports, in order
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::{metadata::importscope::{ImportDeclaration, ImportsInfo}, prelude::*};
    ///
    /// let builder = ImportScopeBuilder::new()
    ///     .parent(0)
    ///     .declarations(ImportsInfo::with_declarations(vec![
    ///         ImportDeclaration::ImportNamespace {
    ///             namespace: "System.Collections.Generic".to_string(),
    ///         },
    ///         ImportDeclaration::DefineNamespaceAlias {
    ///             alias: "IO".to_string(),
    ///             namespace: "System.IO".to_string(),
    ///         },
    ///     ]));
    /// ```
    #[must_use]
    pub fn declarations(mut self, declarations: ImportsInfo) -> Self {
        self.declarations = Some(declarations);
        self.imports = None;
        self
    }

    /// Builds and adds the `ImportScope` entry to the metadata
    ///
    /// Validates all required fields, creates the `ImportScope` table entry,
    /// and adds it to the CIL assembly. Returns a token that can be used
    /// to reference this import scope.
    ///
    /// # Parameters
    /// - `assembly`: Mutable reference to the CIL assembly
    ///
    /// # Returns
    /// - `Ok(Token)`: Token referencing the created import scope
    /// - `Err(Error)`: If validation fails or table operations fail
    ///
    /// # Errors
    /// - Missing required field (parent or imports)
    /// - Table operations fail due to metadata constraints
    /// - Import scope validation failed
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
    /// let mut assembly = CilAssembly::new(view);
    /// let imports_data = vec![0x01, 0x02, 0x03];
    /// let token = ImportScopeBuilder::new()
    ///     .parent(0)
    ///     .imports(&imports_data)
    ///     .build(&mut assembly)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let parent = self.parent.ok_or_else(|| {
            Error::ModificationInvalid(
                "Parent scope index is required for ImportScope (use 0 for root scope)".to_string(),
            )
        })?;

        let imports_index = match (self.declarations, self.imports) {
            (Some(declarations), _) => {
                let mut imports = Vec::with_capacity(declarations.len());
                for declaration in declarations.iter() {
                    imports.push(composite_import(assembly, declaration)?);
                }
                assembly
                    .blob_add_composite(BlobComposite::Imports(imports))
                    .placeholder()
            }
            (None, Some(imports)) if imports.is_empty() => 0,
            (None, Some(imports)) => assembly.blob_add(&imports)?.placeholder(),
            (None, None) => {
                return Err(Error::ModificationInvalid(
                    "Import blob data is required for ImportScope".to_string(),
                ))
            }
        };

        let import_scope = ImportScopeRaw {
            rid: 0,
            token: Token::new(0),
            offset: 0,
            parent,
            imports: imports_index,
        };

        assembly.table_row_add(
            TableId::ImportScope,
            TableDataOwned::ImportScope(import_scope),
        )
    }
}

/// A declaration as the writer encodes it: its text added as blobs (an empty one is index 0),
/// its assembly as an AssemblyRef row.
fn composite_import(
    assembly: &mut CilAssembly,
    declaration: &ImportDeclaration,
) -> Result<CompositeImport> {
    let mut text = |value: &str| -> Result<Option<ChangeRefRc>> {
        if value.is_empty() {
            Ok(None)
        } else {
            assembly.blob_add(value.as_bytes()).map(Some)
        }
    };
    let assembly_row = |token: Token| -> Result<u32> {
        if token.table() == TableId::AssemblyRef as u8 {
            Ok(token.row())
        } else {
            Err(Error::ModificationInvalid(format!(
                "an import names assembly {token}, which is not an AssemblyRef"
            )))
        }
    };
    let mut import = CompositeImport {
        kind: ImportKind::ImportNamespace,
        alias: None,
        assembly: 0,
        namespace: None,
        target: None,
    };
    match declaration {
        ImportDeclaration::ImportNamespace { namespace } => {
            import.namespace = text(namespace)?;
        }
        ImportDeclaration::ImportAssemblyNamespace {
            assembly_ref,
            namespace,
        } => {
            import.kind = ImportKind::ImportAssemblyNamespace;
            import.assembly = assembly_row(*assembly_ref)?;
            import.namespace = text(namespace)?;
        }
        ImportDeclaration::ImportType { type_ref } => {
            import.kind = ImportKind::ImportType;
            import.target = Some(*type_ref);
        }
        ImportDeclaration::ImportXmlNamespace { alias, namespace } => {
            import.kind = ImportKind::ImportXmlNamespace;
            import.alias = text(alias)?;
            import.namespace = text(namespace)?;
        }
        ImportDeclaration::ImportAssemblyReferenceAlias { alias } => {
            import.kind = ImportKind::ImportAssemblyReferenceAlias;
            import.alias = text(alias)?;
        }
        ImportDeclaration::DefineAssemblyAlias {
            alias,
            assembly_ref,
        } => {
            import.kind = ImportKind::DefineAssemblyAlias;
            import.alias = text(alias)?;
            import.assembly = assembly_row(*assembly_ref)?;
        }
        ImportDeclaration::DefineNamespaceAlias { alias, namespace } => {
            import.kind = ImportKind::DefineNamespaceAlias;
            import.alias = text(alias)?;
            import.namespace = text(namespace)?;
        }
        ImportDeclaration::DefineAssemblyNamespaceAlias {
            alias,
            assembly_ref,
            namespace,
        } => {
            import.kind = ImportKind::DefineAssemblyNamespaceAlias;
            import.alias = text(alias)?;
            import.assembly = assembly_row(*assembly_ref)?;
            import.namespace = text(namespace)?;
        }
        ImportDeclaration::DefineTypeAlias { alias, type_ref } => {
            import.kind = ImportKind::DefineTypeAlias;
            import.alias = text(alias)?;
            import.target = Some(*type_ref);
        }
    }
    Ok(import)
}

impl Default for ImportScopeBuilder {
    /// Creates a default `ImportScopeBuilder`
    ///
    /// Equivalent to calling [`ImportScopeBuilder::new()`].
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::ChangeRefKind, testkit::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_importscope_builder_new() {
        let builder = ImportScopeBuilder::new();

        assert!(builder.parent.is_none());
        assert!(builder.imports.is_none());
    }

    #[test]
    fn test_importscope_builder_default() {
        let builder = ImportScopeBuilder::default();

        assert!(builder.parent.is_none());
        assert!(builder.imports.is_none());
    }

    #[test]
    fn test_importscope_builder_root_scope() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let imports_data = vec![0x01, 0x10, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6D]; // System namespace
        let ref_ = ImportScopeBuilder::new()
            .parent(0) // Root scope
            .imports(&imports_data)
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::ImportScope));
        Ok(())
    }

    #[test]
    fn test_importscope_builder_child_scope() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let imports_data = vec![0x01, 0x02, 0x03];
        let ref_ = ImportScopeBuilder::new()
            .parent(1) // Child scope referencing parent
            .imports(&imports_data)
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::ImportScope));
        Ok(())
    }

    #[test]
    fn test_importscope_builder_empty_imports() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = ImportScopeBuilder::new()
            .parent(0)
            .imports(&[]) // Empty imports
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::ImportScope));
        Ok(())
    }

    #[test]
    fn test_importscope_builder_missing_parent() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let imports_data = vec![0x01, 0x02];
        let result = ImportScopeBuilder::new()
            .imports(&imports_data)
            .build(&mut assembly);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalid(details) => {
                assert!(details.contains("Parent scope index is required"));
            }
            _ => panic!("Expected ModificationInvalid error"),
        }
        Ok(())
    }

    #[test]
    fn test_importscope_builder_missing_imports() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let result = ImportScopeBuilder::new().parent(0).build(&mut assembly);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalid(details) => {
                assert!(details.contains("Import blob data is required"));
            }
            _ => panic!("Expected ModificationInvalid error"),
        }
        Ok(())
    }

    #[test]
    fn test_importscope_builder_clone() {
        let imports_data = vec![0x01, 0x02, 0x03];
        let builder = ImportScopeBuilder::new().parent(0).imports(&imports_data);

        let cloned = builder.clone();
        assert_eq!(builder.parent, cloned.parent);
        assert_eq!(builder.imports, cloned.imports);
    }

    #[test]
    fn test_importscope_builder_debug() {
        let imports_data = vec![0x01, 0x02, 0x03];
        let builder = ImportScopeBuilder::new().parent(1).imports(&imports_data);

        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("ImportScopeBuilder"));
        assert!(debug_str.contains("parent"));
        assert!(debug_str.contains("imports"));
    }

    #[test]
    fn test_importscope_builder_fluent_interface() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let imports_data = vec![0x01, 0x05, 0x54, 0x65, 0x73, 0x74, 0x73]; // Tests namespace

        // Test method chaining
        let ref_ = ImportScopeBuilder::new()
            .parent(0)
            .imports(&imports_data)
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::ImportScope));
        Ok(())
    }

    #[test]
    fn test_importscope_builder_multiple_builds() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let imports1 = vec![0x01, 0x02];
        let imports2 = vec![0x03, 0x04];

        // Build first scope
        let ref1 = ImportScopeBuilder::new()
            .parent(0)
            .imports(&imports1)
            .build(&mut assembly)
            .expect("Should build first scope");

        // Build second scope
        let ref2 = ImportScopeBuilder::new()
            .parent(1) // Child of first scope
            .imports(&imports2)
            .build(&mut assembly)
            .expect("Should build second scope");

        assert_eq!(ref1.kind(), ChangeRefKind::TableRow(TableId::ImportScope));
        assert_eq!(ref2.kind(), ChangeRefKind::TableRow(TableId::ImportScope));
        assert!(!std::sync::Arc::ptr_eq(&ref1, &ref2));
        Ok(())
    }
}

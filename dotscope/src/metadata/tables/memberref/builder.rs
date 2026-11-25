//! MemberRefBuilder for creating external member reference definitions.
//!
//! This module provides [`crate::metadata::tables::memberref::MemberRefBuilder`] for creating MemberRef table entries
//! with a fluent API. Member references enable cross-assembly member access by
//! defining references to fields and methods in external assemblies, modules,
//! and type instantiations without requiring the actual implementation at compile time.

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{CodedIndex, CodedIndexType, MemberRefRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating MemberRef metadata entries.
///
/// `MemberRefBuilder` provides a fluent API for creating MemberRef table entries
/// with validation and automatic heap management. Member references define external
/// member access patterns enabling cross-assembly interoperability, late binding,
/// dynamic member access, and generic type instantiation scenarios.
///
/// # Member Reference Model
///
/// .NET member references follow a standard pattern:
/// - **Declaring Context**: The type, module, or method that declares the member
/// - **Member Identity**: The name and signature that uniquely identifies the member
/// - **Signature Information**: Type information for proper invocation and access
/// - **External Resolution**: Runtime resolution to actual implementation
///
/// # Coded Index Types
///
/// Member references use the `MemberRefParent` coded index to specify the declaring context:
/// - **TypeDef**: Members declared in current assembly types
/// - **TypeRef**: Members declared in external assembly types  
/// - **ModuleRef**: Global members declared in external modules
/// - **MethodDef**: Vararg method signatures referencing specific methods
/// - **TypeSpec**: Members of generic type instantiations
///
/// # Member Types
///
/// Member references support two fundamental member types:
/// - **Method References**: Constructor calls, method invocations, function pointers
/// - **Field References**: Field access, property backing fields, static data
///
/// # Examples
///
/// ```rust,no_run
/// # use dotscope::prelude::*;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// let mut assembly = CilAssembly::new(view);
///
///
/// // Create a method reference to external assembly
/// let external_type = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::MemberRefParent); // System.String from mscorlib
/// let method_signature = &[0x20, 0x01, 0x01, 0x0E]; // Default instance method, 1 param, void return, string param
///
/// let string_concat_ref = MemberRefBuilder::new()
///     .class(external_type.clone())
///     .name("Concat")
///     .signature(method_signature)
///     .build(&mut assembly)?;
///
/// // Create a field reference to external type
/// let field_signature = &[0x06, 0x08]; // Field signature, int32 type
/// let field_ref = MemberRefBuilder::new()
///     .class(external_type.clone())
///     .name("Length")
///     .signature(field_signature)
///     .build(&mut assembly)?;
///
/// // Create a constructor reference
/// let ctor_signature = &[0x20, 0x01, 0x01, 0x1C]; // Default instance method, 1 param, void return, object param
/// let ctor_ref = MemberRefBuilder::new()
///     .class(external_type)
///     .name(".ctor")
///     .signature(ctor_signature)
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct MemberRefBuilder {
    class: Option<CodedIndex>,
    name: Option<String>,
    signature: Option<Vec<u8>>,
}

impl Default for MemberRefBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MemberRefBuilder {
    /// Creates a new MemberRefBuilder.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::tables::memberref::MemberRefBuilder`] instance ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            class: None,
            name: None,
            signature: None,
        }
    }

    /// Sets the declaring class, module, or method for this member reference.
    ///
    /// The class must be a valid `MemberRefParent` coded index that references
    /// the context where this member is declared. This establishes the scope
    /// for member resolution and access validation.
    ///
    /// Valid class types include:
    /// - `TypeDef` - Members declared in current assembly types
    /// - `TypeRef` - Members declared in external assembly types
    /// - `ModuleRef` - Global members declared in external modules
    /// - `MethodDef` - Vararg method signatures referencing specific methods
    /// - `TypeSpec` - Members of generic type instantiations
    ///
    /// # Arguments
    ///
    /// * `class` - A `MemberRefParent` coded index pointing to the declaring context
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn class(mut self, class: CodedIndex) -> Self {
        self.class = Some(class);
        self
    }

    /// Sets the member name for identification and access.
    ///
    /// Member names are used for resolution, binding, and reflection operations.
    /// Common naming patterns include:
    /// - Standard method names: "ToString", "GetHashCode", "Equals"
    /// - Constructor names: ".ctor" (instance), ".cctor" (static)  
    /// - Field names: "value__" (enum backing), descriptive identifiers
    /// - Property accessor names: "get_PropertyName", "set_PropertyName"
    ///
    /// # Arguments
    ///
    /// * `name` - The member name (must be a valid identifier)
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the member signature for type information and calling conventions.
    ///
    /// The signature defines the member's type structure using ECMA-335 signature
    /// encoding. The signature format depends on the member type being referenced.
    ///
    /// Method signature patterns:
    /// - `[0x20, 0x00, 0x01]` - Default instance method, no params, void return
    /// - `[0x00, 0x01, 0x08, 0x08]` - Static method, 1 param, int32 return, int32 param
    /// - `[0x20, 0x02, 0x0E, 0x08, 0x1C]` - Instance method, 2 params, string return, int32+object params
    ///
    /// Field signature patterns:
    /// - `[0x06, 0x08]` - Field signature, int32 type
    /// - `[0x06, 0x0E]` - Field signature, string type
    /// - `[0x06, 0x1C]` - Field signature, object type
    ///
    /// # Arguments
    ///
    /// * `signature` - The member signature bytes
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn signature(mut self, signature: &[u8]) -> Self {
        self.signature = Some(signature.to_vec());
        self
    }

    /// Builds the member reference and adds it to the assembly.
    ///
    /// This method validates all required fields are set, adds the name and
    /// signature to the appropriate heaps, creates the raw member reference structure,
    /// and adds it to the MemberRef table.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The CilAssembly for managing the assembly
    ///
    /// # Returns
    ///
    /// A [`crate::metadata::token::Token`] representing the newly created member reference, or an error if
    /// validation fails or required fields are missing.
    ///
    /// # Errors
    ///
    /// - Returns error if class is not set
    /// - Returns error if name is not set
    /// - Returns error if signature is not set
    /// - Returns error if class is not a valid MemberRefParent coded index
    /// - Returns error if heap operations fail
    /// - Returns error if table operations fail
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let class = self
            .class
            .ok_or_else(|| Error::ModificationInvalid("MemberRef class is required".to_string()))?;

        let name = self
            .name
            .ok_or_else(|| Error::ModificationInvalid("MemberRef name is required".to_string()))?;

        let signature = self.signature.ok_or_else(|| {
            Error::ModificationInvalid("MemberRef signature is required".to_string())
        })?;

        let valid_class_tables = CodedIndexType::MemberRefParent.tables();
        if !valid_class_tables.contains(&class.tag) {
            return Err(Error::ModificationInvalid(format!(
                "Class must be a MemberRefParent coded index (TypeDef/TypeRef/ModuleRef/MethodDef/TypeSpec), got {:?}",
                class.tag
            )));
        }

        let name_index = assembly.string_get_or_add(&name)?.placeholder();
        let signature_index = assembly.blob_add(&signature)?.placeholder();
        let rid = assembly.next_rid(TableId::MemberRef)?;

        let token_value = ((TableId::MemberRef as u32) << 24) | rid;
        let token = Token::new(token_value);

        let memberref_raw = MemberRefRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            class,
            name: name_index,
            signature: signature_index,
        };

        assembly.table_row_add(TableId::MemberRef, TableDataOwned::MemberRef(memberref_raw))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        cilassembly::CilAssembly, metadata::cilassemblyview::CilAssemblyView, testkit::fixture,
    };

    #[test]
    fn test_memberref_builder_basic() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Create a MemberRefParent coded index (TypeRef)
        let declaring_type = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::MemberRefParent);

        // Create a method signature for a simple method
        let method_signature = &[0x20, 0x00, 0x01]; // Default instance method, no params, void return

        let ref_ = MemberRefBuilder::new()
            .class(declaring_type)
            .name("ToString")
            .signature(method_signature)
            .build(&mut assembly)
            .unwrap();

        // Verify ref is created correctly
        assert_eq!(
            ref_.kind(),
            crate::cilassembly::ChangeRefKind::TableRow(TableId::MemberRef)
        );
    }

    #[test]
    fn test_memberref_builder_field_reference() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let declaring_type = CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::MemberRefParent); // Local type

        // Create a field signature
        let field_signature = &[0x06, 0x08]; // Field signature, int32 type

        let ref_ = MemberRefBuilder::new()
            .class(declaring_type)
            .name("m_value")
            .signature(field_signature)
            .build(&mut assembly)
            .unwrap();

        // Verify ref is created correctly
        assert_eq!(
            ref_.kind(),
            crate::cilassembly::ChangeRefKind::TableRow(TableId::MemberRef)
        );
    }

    #[test]
    fn test_memberref_builder_constructor_reference() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let declaring_type = CodedIndex::new(TableId::TypeRef, 2, CodedIndexType::MemberRefParent);

        // Create a constructor signature
        let ctor_signature = &[0x20, 0x01, 0x01, 0x1C]; // Default instance method, 1 param, void return, object param

        let ref_ = MemberRefBuilder::new()
            .class(declaring_type)
            .name(".ctor")
            .signature(ctor_signature)
            .build(&mut assembly)
            .unwrap();

        // Verify ref is created correctly
        assert_eq!(
            ref_.kind(),
            crate::cilassembly::ChangeRefKind::TableRow(TableId::MemberRef)
        );
    }

    #[test]
    fn test_memberref_builder_module_reference() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let module_ref = CodedIndex::new(TableId::ModuleRef, 1, CodedIndexType::MemberRefParent); // External module

        // Create a method signature for global function
        let global_method_sig = &[0x00, 0x01, 0x08, 0x08]; // Static method, 1 param, int32 return, int32 param

        let ref_ = MemberRefBuilder::new()
            .class(module_ref)
            .name("GlobalFunction")
            .signature(global_method_sig)
            .build(&mut assembly)
            .unwrap();

        // Verify ref is created correctly
        assert_eq!(
            ref_.kind(),
            crate::cilassembly::ChangeRefKind::TableRow(TableId::MemberRef)
        );
    }

    #[test]
    fn test_memberref_builder_generic_type_reference() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let generic_type = CodedIndex::new(TableId::TypeSpec, 1, CodedIndexType::MemberRefParent); // Generic type instantiation

        // Create a method signature
        let method_signature = &[0x20, 0x01, 0x0E, 0x1C]; // Default instance method, 1 param, string return, object param

        let ref_ = MemberRefBuilder::new()
            .class(generic_type)
            .name("GetValue")
            .signature(method_signature)
            .build(&mut assembly)
            .unwrap();

        // Verify ref is created correctly
        assert_eq!(
            ref_.kind(),
            crate::cilassembly::ChangeRefKind::TableRow(TableId::MemberRef)
        );
    }

    #[test]
    fn test_memberref_builder_missing_class() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let result = MemberRefBuilder::new()
            .name("TestMethod")
            .signature(&[0x20, 0x00, 0x01])
            .build(&mut assembly);

        // Should fail because class is required
        assert!(result.is_err());
    }

    #[test]
    fn test_memberref_builder_missing_name() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let declaring_type = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::MemberRefParent);

        let result = MemberRefBuilder::new()
            .class(declaring_type)
            .signature(&[0x20, 0x00, 0x01])
            .build(&mut assembly);

        // Should fail because name is required
        assert!(result.is_err());
    }

    #[test]
    fn test_memberref_builder_missing_signature() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let declaring_type = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::MemberRefParent);

        let result = MemberRefBuilder::new()
            .class(declaring_type)
            .name("TestMethod")
            .build(&mut assembly);

        // Should fail because signature is required
        assert!(result.is_err());
    }

    #[test]
    fn test_memberref_builder_invalid_class_type() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Use a table type that's not valid for MemberRefParent
        let invalid_class = CodedIndex::new(TableId::Field, 1, CodedIndexType::MemberRefParent); // Field not in MemberRefParent

        let result = MemberRefBuilder::new()
            .class(invalid_class)
            .name("TestMethod")
            .signature(&[0x20, 0x00, 0x01])
            .build(&mut assembly);

        // Should fail because class type is not valid for MemberRefParent
        assert!(result.is_err());
    }

    #[test]
    fn test_memberref_builder_multiple_member_refs() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let type_ref1 = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::MemberRefParent);
        let type_ref2 = CodedIndex::new(TableId::TypeRef, 2, CodedIndexType::MemberRefParent);
        let type_def1 = CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::MemberRefParent);

        let method_sig = &[0x20, 0x00, 0x01]; // Default instance method, no params, void return
        let field_sig = &[0x06, 0x08]; // Field signature, int32

        // Create multiple member references
        let member1 = MemberRefBuilder::new()
            .class(type_ref1)
            .name("Method1")
            .signature(method_sig)
            .build(&mut assembly)
            .unwrap();

        let member2 = MemberRefBuilder::new()
            .class(type_ref2.clone())
            .name("Field1")
            .signature(field_sig)
            .build(&mut assembly)
            .unwrap();

        let member3 = MemberRefBuilder::new()
            .class(type_def1)
            .name("Method2")
            .signature(method_sig)
            .build(&mut assembly)
            .unwrap();

        let member4 = MemberRefBuilder::new()
            .class(type_ref2)
            .name(".ctor")
            .signature(&[0x20, 0x01, 0x01, 0x08]) // Constructor with int32 param
            .build(&mut assembly)
            .unwrap();

        // All should succeed and have unique refs
        assert!(!std::sync::Arc::ptr_eq(&member1, &member2));
        assert!(!std::sync::Arc::ptr_eq(&member2, &member3));
        assert!(!std::sync::Arc::ptr_eq(&member3, &member4));

        // All should have MemberRef table kind
        assert_eq!(
            member1.kind(),
            crate::cilassembly::ChangeRefKind::TableRow(TableId::MemberRef)
        );
        assert_eq!(
            member2.kind(),
            crate::cilassembly::ChangeRefKind::TableRow(TableId::MemberRef)
        );
        assert_eq!(
            member3.kind(),
            crate::cilassembly::ChangeRefKind::TableRow(TableId::MemberRef)
        );
        assert_eq!(
            member4.kind(),
            crate::cilassembly::ChangeRefKind::TableRow(TableId::MemberRef)
        );
    }
}

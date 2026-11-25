//! MethodDefBuilder for creating method definitions.
//!
//! This module provides [`crate::metadata::tables::methoddef::MethodDefBuilder`] for creating MethodDef table entries
//! with a fluent API. Methods define the behavior of types including instance
//! methods, static methods, constructors, and property/event accessors with their
//! signatures, parameters, and implementation details.

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{MethodDefRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating MethodDef metadata entries.
///
/// `MethodDefBuilder` provides a fluent API for creating MethodDef table entries
/// with validation and automatic heap management. MethodDef entries define
/// method implementations including their signatures, parameters, and implementation
/// characteristics such as RVA, flags, and parameter lists.
///
/// # Examples
///
/// ```rust,no_run
/// # use dotscope::prelude::*;
/// # use dotscope::metadata::tables::MethodDefBuilder;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// let mut assembly = CilAssembly::new(view);
///
///
/// // Create a method signature for void method with no parameters
/// let void_signature = &[0x00, 0x00, 0x01]; // DEFAULT calling convention, 0 params, VOID return
///
/// // Create a public static method
/// let my_method = MethodDefBuilder::new()
///     .name("MyMethod")
///     .flags(0x0016) // Public | Static
///     .impl_flags(0x0000) // IL
///     .signature(void_signature)
///     .rva(0) // No implementation yet
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct MethodDefBuilder {
    name: Option<String>,
    flags: Option<u32>,
    impl_flags: Option<u32>,
    signature: Option<Vec<u8>>,
    rva: Option<u32>,
    param_list: Option<u32>,
}

impl MethodDefBuilder {
    /// Creates a new MethodDefBuilder.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::tables::methoddef::MethodDefBuilder`] instance ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: None,
            flags: None,
            impl_flags: None,
            signature: None,
            rva: None,
            param_list: None,
        }
    }

    /// Sets the method name.
    ///
    /// Common method names include:
    /// - ".ctor" for instance constructors
    /// - ".cctor" for static constructors (type initializers)
    /// - Regular identifier names for other methods
    ///
    /// # Arguments
    ///
    /// * `name` - The method name (must be a valid identifier or special name)
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the method flags (attributes).
    ///
    /// Method flags control accessibility, virtual dispatch, and special behaviors.
    /// Common flag combinations:
    ///
    /// **Access Modifiers:**
    /// - `0x0001`: CompilerControlled
    /// - `0x0002`: Private
    /// - `0x0003`: FamANDAssem (Family AND Assembly)
    /// - `0x0004`: Assem (Assembly/Internal)
    /// - `0x0005`: Family (Protected)
    /// - `0x0006`: FamORAssem (Family OR Assembly)
    /// - `0x0007`: Public
    ///
    /// **Method Type:**
    /// - `0x0010`: Static
    /// - `0x0020`: Final
    /// - `0x0040`: Virtual
    /// - `0x0080`: HideBySig
    /// - `0x0100`: CheckAccessOnOverride
    /// - `0x0200`: Abstract
    /// - `0x0400`: SpecialName
    /// - `0x0800`: PinvokeImpl
    /// - `0x1000`: UnmanagedExport
    /// - `0x2000`: RTSpecialName
    /// - `0x4000`: HasSecurity
    /// - `0x8000`: RequireSecObject
    ///
    /// # Arguments
    ///
    /// * `flags` - The method attribute flags bitmask
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn flags(mut self, flags: u32) -> Self {
        self.flags = Some(flags);
        self
    }

    /// Sets the method implementation flags.
    ///
    /// Implementation flags control how the method is implemented and executed.
    /// Common values:
    /// - `0x0000`: IL (Intermediate Language)
    /// - `0x0001`: Native (Platform-specific native code)
    /// - `0x0002`: OPTIL (Optimized IL)
    /// - `0x0003`: Runtime (Provided by runtime)
    /// - `0x0004`: Unmanaged (Unmanaged code)
    /// - `0x0008`: NoInlining (Prevent inlining)
    /// - `0x0010`: ForwardRef (Forward reference)
    /// - `0x0020`: Synchronized (Thread synchronization)
    /// - `0x0040`: NoOptimization (Disable optimizations)
    /// - `0x0080`: PreserveSig (Preserve signature)
    /// - `0x0100`: InternalCall (Internal runtime call)
    ///
    /// # Arguments
    ///
    /// * `impl_flags` - The method implementation flags bitmask
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn impl_flags(mut self, impl_flags: u32) -> Self {
        self.impl_flags = Some(impl_flags);
        self
    }

    /// Sets the method signature.
    ///
    /// The signature defines the method's calling convention, parameters, and return type
    /// using ECMA-335 signature encoding. The signature format is:
    ///
    /// 1. Calling convention (1 byte)
    /// 2. Parameter count (compressed integer)
    /// 3. Return type (type signature)
    /// 4. Parameter types (type signatures)
    ///
    /// Common calling conventions:
    /// - `0x00`: DEFAULT (instance method)
    /// - `0x10`: VARARG (variable arguments)
    /// - `0x20`: GENERIC (generic method)
    ///
    /// # Arguments
    ///
    /// * `signature` - The method signature bytes
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn signature(mut self, signature: &[u8]) -> Self {
        self.signature = Some(signature.to_vec());
        self
    }

    /// Sets the relative virtual address (RVA) of the method implementation.
    ///
    /// The RVA points to the method's implementation within the PE file:
    /// - `0`: Abstract method, interface method, or extern method without implementation
    /// - Non-zero: Points to IL code or native implementation
    ///
    /// # Arguments
    ///
    /// * `rva` - The relative virtual address
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn rva(mut self, rva: u32) -> Self {
        self.rva = Some(rva);
        self
    }

    /// Sets the parameter list starting index.
    ///
    /// This points to the first parameter in the Param table for this method.
    /// Parameters are stored as a contiguous range in the Param table, up to the next
    /// method's start (ECMA-335 II.22.26). Without it, the method starts an empty list at the
    /// next Param row, so the parameters added after it are its own.
    ///
    /// # Arguments
    ///
    /// * `param_list` - The index into the Param table
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn param_list(mut self, param_list: u32) -> Self {
        self.param_list = Some(param_list);
        self
    }

    /// Builds the method and adds it to the assembly.
    ///
    /// This method validates all required fields are set, adds the name and
    /// signature to the appropriate heaps, creates the raw method structure,
    /// and adds it to the MethodDef table.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The CilAssembly for managing the assembly
    ///
    /// # Returns
    ///
    /// A [`ChangeRefRc`] that will resolve to the method's token after the assembly is written.
    /// Use `token()` on the returned reference after writing to get the actual token value.
    ///
    /// # Errors
    ///
    /// - Returns error if name is not set
    /// - Returns error if flags are not set
    /// - Returns error if impl_flags are not set
    /// - Returns error if signature is not set
    /// - Returns error if heap operations fail
    /// - Returns error if table operations fail
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let name = self
            .name
            .ok_or_else(|| Error::ModificationInvalid("Method name is required".to_string()))?;

        let flags = self
            .flags
            .ok_or_else(|| Error::ModificationInvalid("Method flags are required".to_string()))?;

        let impl_flags = self.impl_flags.ok_or_else(|| {
            Error::ModificationInvalid("Method implementation flags are required".to_string())
        })?;

        let signature = self.signature.ok_or_else(|| {
            Error::ModificationInvalid("Method signature is required".to_string())
        })?;

        let rva = self.rva.unwrap_or(0); // Default to 0 (abstract/interface method)
        let param_list = match self.param_list {
            Some(list) => list,
            None => assembly.next_rid(TableId::Param)?,
        };
        let name_index = assembly.string_get_or_add(&name)?.placeholder();
        let signature_index = assembly.blob_add(&signature)?.placeholder();
        let rid = assembly.next_rid(TableId::MethodDef)?;

        // Create a placeholder token - will be updated when ChangeRef is resolved
        let placeholder_token = Token::from_parts(TableId::MethodDef, rid);

        let method_raw = MethodDefRaw {
            rid,
            token: placeholder_token,
            offset: 0, // Will be set during binary generation
            rva,
            impl_flags,
            flags,
            name: name_index,
            signature: signature_index,
            param_list,
        };

        // Add the method to the table and return the ChangeRefRc
        assembly.table_row_add(TableId::MethodDef, TableDataOwned::MethodDef(method_raw))
    }
}

impl Default for MethodDefBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        cilassembly::{ChangeRefKind, CilAssembly},
        metadata::method::{MethodAccessFlags, MethodImplCodeType, MethodModifiers},
        testkit::fixture,
    };

    #[test]
    fn test_method_builder_basic() {
        let path = fixture("WindowsBase.dll");
        let mut assembly = CilAssembly::from_path(&path).expect("the fixture loads");
        // Check existing MethodDef table count
        let existing_method_count = assembly.original_table_row_count(TableId::MethodDef);
        let _expected_rid = existing_method_count + 1;

        // Create a void method signature with no parameters
        // Format: [calling_convention, param_count, return_type]
        let void_signature = &[0x00, 0x00, 0x01]; // DEFAULT, 0 params, VOID

        let ref_ = MethodDefBuilder::new()
            .name("TestMethod")
            .flags(MethodAccessFlags::PUBLIC.bits() | MethodModifiers::HIDE_BY_SIG.bits())
            .impl_flags(MethodImplCodeType::IL.bits())
            .signature(void_signature)
            .rva(0) // No implementation
            .build(&mut assembly)
            .unwrap();

        // Verify reference is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::MethodDef));
        // MethodDef table
    }

    #[test]
    fn test_method_builder_static_constructor() {
        let path = fixture("WindowsBase.dll");
        let mut assembly = CilAssembly::from_path(&path).expect("the fixture loads");
        // Static constructor signature
        let static_ctor_sig = &[0x00, 0x00, 0x01]; // DEFAULT, 0 params, VOID

        let ref_ = MethodDefBuilder::new()
            .name(".cctor")
            .flags(
                MethodAccessFlags::PRIVATE.bits()
                    | MethodModifiers::STATIC.bits()
                    | MethodModifiers::SPECIAL_NAME.bits()
                    | MethodModifiers::RTSPECIAL_NAME.bits(),
            )
            .impl_flags(MethodImplCodeType::IL.bits())
            .signature(static_ctor_sig)
            .build(&mut assembly)
            .unwrap();

        // Verify reference is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::MethodDef));
    }

    #[test]
    fn test_method_builder_instance_constructor() {
        let path = fixture("WindowsBase.dll");
        let mut assembly = CilAssembly::from_path(&path).expect("the fixture loads");
        // Instance constructor signature
        let instance_ctor_sig = &[0x20, 0x00, 0x01]; // HASTHIS, 0 params, VOID

        let ref_ = MethodDefBuilder::new()
            .name(".ctor")
            .flags(
                MethodAccessFlags::PUBLIC.bits()
                    | MethodModifiers::SPECIAL_NAME.bits()
                    | MethodModifiers::RTSPECIAL_NAME.bits(),
            )
            .impl_flags(MethodImplCodeType::IL.bits())
            .signature(instance_ctor_sig)
            .build(&mut assembly)
            .unwrap();

        // Verify reference is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::MethodDef));
    }

    #[test]
    fn test_method_builder_with_return_value() {
        let path = fixture("WindowsBase.dll");
        let mut assembly = CilAssembly::from_path(&path).expect("the fixture loads");
        // Method with return value (int32)
        let method_with_return_sig = &[0x00, 0x00, 0x08]; // DEFAULT, 0 params, I4

        let ref_ = MethodDefBuilder::new()
            .name("GetValue")
            .flags(
                MethodAccessFlags::PUBLIC.bits()
                    | MethodModifiers::STATIC.bits()
                    | MethodModifiers::HIDE_BY_SIG.bits(),
            )
            .impl_flags(MethodImplCodeType::IL.bits())
            .signature(method_with_return_sig)
            .build(&mut assembly)
            .unwrap();

        // Verify reference is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::MethodDef));
    }

    #[test]
    fn test_method_builder_missing_name() {
        let path = fixture("WindowsBase.dll");
        let mut assembly = CilAssembly::from_path(&path).expect("the fixture loads");
        let result = MethodDefBuilder::new()
            .flags(MethodAccessFlags::PUBLIC.bits())
            .impl_flags(MethodImplCodeType::IL.bits())
            .signature(&[0x00, 0x00, 0x01])
            .build(&mut assembly);

        // Should fail because name is required
        assert!(result.is_err());
    }

    #[test]
    fn test_method_builder_missing_flags() {
        let path = fixture("WindowsBase.dll");
        let mut assembly = CilAssembly::from_path(&path).expect("the fixture loads");
        let result = MethodDefBuilder::new()
            .name("TestMethod")
            .impl_flags(MethodImplCodeType::IL.bits())
            .signature(&[0x00, 0x00, 0x01])
            .build(&mut assembly);

        // Should fail because flags are required
        assert!(result.is_err());
    }

    #[test]
    fn test_method_builder_missing_impl_flags() {
        let path = fixture("WindowsBase.dll");
        let mut assembly = CilAssembly::from_path(&path).expect("the fixture loads");
        let result = MethodDefBuilder::new()
            .name("TestMethod")
            .flags(MethodAccessFlags::PUBLIC.bits())
            .signature(&[0x00, 0x00, 0x01])
            .build(&mut assembly);

        // Should fail because impl_flags are required
        assert!(result.is_err());
    }

    #[test]
    fn test_method_builder_missing_signature() {
        let path = fixture("WindowsBase.dll");
        let mut assembly = CilAssembly::from_path(&path).expect("the fixture loads");
        let result = MethodDefBuilder::new()
            .name("TestMethod")
            .flags(MethodAccessFlags::PUBLIC.bits())
            .impl_flags(MethodImplCodeType::IL.bits())
            .build(&mut assembly);

        // Should fail because signature is required
        assert!(result.is_err());
    }

    #[test]
    fn test_method_builder_multiple_methods() {
        let path = fixture("WindowsBase.dll");
        let mut assembly = CilAssembly::from_path(&path).expect("the fixture loads");
        let void_signature = &[0x00, 0x00, 0x01]; // void return

        // Create multiple methods
        let ref1 = MethodDefBuilder::new()
            .name("Method1")
            .flags(MethodAccessFlags::PRIVATE.bits())
            .impl_flags(MethodImplCodeType::IL.bits())
            .signature(void_signature)
            .build(&mut assembly)
            .unwrap();

        let ref2 = MethodDefBuilder::new()
            .name("Method2")
            .flags(MethodAccessFlags::PUBLIC.bits())
            .impl_flags(MethodImplCodeType::IL.bits())
            .signature(void_signature)
            .build(&mut assembly)
            .unwrap();

        // Both should succeed and be different references
        assert!(!std::sync::Arc::ptr_eq(&ref1, &ref2));
        assert_eq!(ref1.kind(), ChangeRefKind::TableRow(TableId::MethodDef));
        assert_eq!(ref2.kind(), ChangeRefKind::TableRow(TableId::MethodDef));
    }

    #[test]
    fn test_method_builder_default_values() {
        let path = fixture("WindowsBase.dll");
        let mut assembly = CilAssembly::from_path(&path).expect("the fixture loads");
        // Test that optional fields default correctly
        let ref_ = MethodDefBuilder::new()
            .name("AbstractMethod")
            .flags(MethodAccessFlags::PUBLIC.bits() | MethodModifiers::ABSTRACT.bits())
            .impl_flags(MethodImplCodeType::IL.bits())
            .signature(&[0x00, 0x00, 0x01])
            // Not setting RVA or param_list - should default to 0
            .build(&mut assembly)
            .unwrap();

        // Should succeed with default values
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::MethodDef));
    }
}

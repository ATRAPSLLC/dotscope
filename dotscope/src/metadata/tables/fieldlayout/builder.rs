//! FieldLayoutBuilder for creating explicit field layout specifications.
//!
//! This module provides [`crate::metadata::tables::fieldlayout::FieldLayoutBuilder`] for creating FieldLayout table entries
//! with a fluent API. Field layouts specify explicit byte offsets for fields in types
//! with explicit layout control, enabling precise memory layout for P/Invoke interop,
//! performance optimization, and native structure compatibility.

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{FieldLayoutRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating FieldLayout metadata entries.
///
/// `FieldLayoutBuilder` provides a fluent API for creating FieldLayout table entries
/// with validation and automatic table management. Field layouts define explicit byte
/// offsets for fields within types that use explicit layout control, enabling precise
/// memory layout specification for interoperability, performance optimization, and
/// compatibility scenarios.
///
/// # Explicit Layout Model
///
/// .NET explicit layout follows a structured pattern:
/// - **Containing Type**: Must be marked with `StructLayout(LayoutKind.Explicit)`
/// - **Field Offset**: Explicit byte position within the type's memory layout
/// - **Field Reference**: Direct reference to the field being positioned
/// - **Memory Control**: Precise control over field placement for optimal alignment
///
/// # Layout Types and Scenarios
///
/// Field layouts are essential for various interoperability scenarios:
/// - **P/Invoke Interop**: Matching native C/C++ struct layouts exactly
/// - **COM Interop**: Implementing COM interface memory layouts
/// - **Performance Critical Types**: Cache-line alignment and SIMD optimization
/// - **Union Types**: Overlapping fields to implement C-style unions
/// - **Legacy Compatibility**: Matching existing binary format specifications
/// - **Memory Mapping**: Direct memory-mapped file and hardware register access
///
/// # Offset Specifications
///
/// Field offsets must follow specific rules:
/// - **Byte Aligned**: Offsets are specified in bytes from the start of the type
/// - **Non-Negative**: Offsets must be ≥ 0 and ≤ `i32::MAX`
/// - **Type Boundaries**: Fields must fit within the declared type size
/// - **Alignment Requirements**: Respect platform and type alignment constraints
/// - **No Gaps Required**: Fields can be packed tightly or have intentional gaps
///
/// # Examples
///
/// ```no_run
/// # use dotscope::prelude::*;
/// # use dotscope::metadata::tables::{FieldBuilder, FieldLayoutBuilder};
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// let mut assembly = CilAssembly::new(view);
///
/// // Create explicit layout for a P/Invoke structure
/// // struct Point { int x; int y; }
/// // `int32` fields (signature `FIELD`, `ELEMENT_TYPE_I4`)
/// let int32_field = |name: &str, assembly: &mut CilAssembly| {
///     FieldBuilder::new()
///         .name(name)
///         .flags(FieldAttributes::PUBLIC)
///         .signature(&[0x06, 0x08])
///         .build(assembly)
/// };
/// let x_field_ref = int32_field("x", &mut assembly)?;
/// let y_field_ref = int32_field("y", &mut assembly)?;
///
/// // X field at offset 0 (start of struct)
/// let x_layout = FieldLayoutBuilder::new()
///     .field(x_field_ref.placeholder())
///     .field_offset(0)
///     .build(&mut assembly)?;
///
/// // Y field at offset 4 (after 4-byte int)
/// let y_layout = FieldLayoutBuilder::new()
///     .field(y_field_ref.placeholder())
///     .field_offset(4)
///     .build(&mut assembly)?;
///
/// // Create a union-like structure with overlapping fields
/// // union Value { int intValue; float floatValue; }
/// let int_field_ref = int32_field("intValue", &mut assembly)?;
/// let float_field_ref = int32_field("floatValue", &mut assembly)?;
///
/// // Both fields start at offset 0 (overlapping)
/// let int_layout = FieldLayoutBuilder::new()
///     .field(int_field_ref.placeholder())
///     .field_offset(0)
///     .build(&mut assembly)?;
///
/// let float_layout = FieldLayoutBuilder::new()
///     .field(float_field_ref.placeholder())
///     .field_offset(0) // Same offset = union behavior
///     .build(&mut assembly)?;
///
/// // Create cache-line aligned fields for performance
/// let cache_field1_ref = int32_field("hot", &mut assembly)?;
/// let cache_field2_ref = int32_field("cold", &mut assembly)?;
///
/// // First field at start
/// let aligned_layout1 = FieldLayoutBuilder::new()
///     .field(cache_field1_ref.placeholder())
///     .field_offset(0)
///     .build(&mut assembly)?;
///
/// // Second field at 64-byte boundary (cache line)
/// let aligned_layout2 = FieldLayoutBuilder::new()
///     .field(cache_field2_ref.placeholder())
///     .field_offset(64)
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct FieldLayoutBuilder {
    field_offset: Option<u32>,
    field: Option<u32>,
}

impl Default for FieldLayoutBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl FieldLayoutBuilder {
    /// Creates a new FieldLayoutBuilder.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::tables::fieldlayout::FieldLayoutBuilder`] instance ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            field_offset: None,
            field: None,
        }
    }

    /// Sets the explicit byte offset for the field.
    ///
    /// The field offset specifies the exact byte position where this field begins
    /// within the containing type's memory layout. Offsets are measured from the
    /// start of the type and must respect alignment and size constraints.
    ///
    /// Offset considerations:
    /// - **Zero-based**: Offset 0 means the field starts at the beginning of the type
    /// - **Byte granularity**: Offsets are specified in bytes, not bits
    /// - **Alignment**: Consider natural alignment requirements for the field type
    /// - **Overlapping**: Multiple fields can have the same offset (union behavior)
    /// - **Gaps**: Intentional gaps between fields are allowed for padding
    /// - **Maximum**: Offset must be ≤ `i32::MAX` (2,147,483,647)
    ///
    /// Common offset patterns:
    /// - **Packed structures**: Sequential offsets with no padding
    /// - **Aligned structures**: Offsets respecting natural type alignment
    /// - **Cache-aligned**: Offsets at 64-byte boundaries for performance
    /// - **Page-aligned**: Offsets at 4KB boundaries for memory mapping
    ///
    /// # Arguments
    ///
    /// * `offset` - The byte offset from the start of the containing type
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn field_offset(mut self, offset: u32) -> Self {
        self.field_offset = Some(offset);
        self
    }

    /// Sets the field that this layout applies to.
    ///
    /// The field must be a valid row index that references a field definition
    /// in the current assembly. This establishes which field will be positioned
    /// at the specified offset within the containing type's layout.
    ///
    /// Field requirements:
    /// - **Valid Index**: Must be a row index or placeholder from a Field ChangeRef
    /// - **Existing Field**: Must reference a field that has been defined
    /// - **Explicit Layout Type**: The containing type must use explicit layout
    /// - **Single Layout**: Each field can have at most one FieldLayout entry
    /// - **Instance Fields**: Only applies to instance fields, not static fields
    ///
    /// Field types that require explicit layout:
    /// - **Primitive Types**: int, float, byte, etc. with specific positioning
    /// - **Value Types**: Custom structs with explicit internal layout
    /// - **Reference Types**: Object references with controlled placement
    /// - **Array Fields**: Fixed-size arrays with explicit positioning
    /// - **Pointer Fields**: Unmanaged pointers with specific alignment needs
    ///
    /// # Arguments
    ///
    /// * `field` - A row index or placeholder pointing to the field being positioned
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn field(mut self, field: u32) -> Self {
        self.field = Some(field);
        self
    }

    /// Builds the field layout and adds it to the assembly.
    ///
    /// This method validates all required fields are set, verifies the field row index
    /// is valid, creates the raw field layout structure, and adds it to the
    /// FieldLayout table with proper token generation and validation.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly being modified
    ///
    /// # Returns
    ///
    /// A [`crate::cilassembly::ChangeRefRc`] representing the newly created field layout, or an error if
    /// validation fails or required fields are missing.
    ///
    /// # Errors
    ///
    /// - Returns error if field_offset is not set
    /// - Returns error if field is not set
    /// - Returns error if field row index is 0 (invalid RID, unless it's a placeholder)
    /// - Returns error if offset exceeds maximum allowed value
    /// - Returns error if table operations fail
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let field_offset = self
            .field_offset
            .ok_or_else(|| Error::ModificationInvalid("Field offset is required".to_string()))?;

        let field = self
            .field
            .ok_or_else(|| Error::ModificationInvalid("Field reference is required".to_string()))?;

        // Validate field row index (0 is invalid unless it's a placeholder with high bit set)
        if field == 0 {
            return Err(Error::ModificationInvalid(
                "Field row index cannot be 0".to_string(),
            ));
        }

        // Note: u32::MAX is reserved as "missing offset" indicator in some contexts
        if field_offset == u32::MAX {
            return Err(Error::ModificationInvalid(
                "Field offset cannot be 0xFFFFFFFF (reserved value)".to_string(),
            ));
        }

        let rid = assembly.next_rid(TableId::FieldLayout)?;

        let token_value = ((TableId::FieldLayout as u32) << 24) | rid;
        let token = Token::new(token_value);

        let field_layout_raw = FieldLayoutRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            field_offset,
            field,
        };

        assembly.table_row_add(
            TableId::FieldLayout,
            TableDataOwned::FieldLayout(field_layout_raw),
        )
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        cilassembly::{ChangeRefKind, CilAssembly},
        metadata::cilassemblyview::CilAssemblyView,
        testkit::fixture,
    };

    #[test]
    fn test_field_layout_builder_basic() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Create a basic field layout
        let field_row = 1u32; // Field RID 1

        let layout_ref = FieldLayoutBuilder::new()
            .field(field_row)
            .field_offset(0)
            .build(&mut assembly)
            .unwrap();

        // Verify reference has correct kind
        assert_eq!(
            layout_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldLayout)
        );
    }

    #[test]
    fn test_field_layout_builder_different_offsets() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Test various common offset values
        let field1 = 1u32; // Field RID 1
        let field2 = 2u32; // Field RID 2
        let field3 = 3u32; // Field RID 3
        let field4 = 4u32; // Field RID 4

        // Offset 0 (start of structure)
        let layout1 = FieldLayoutBuilder::new()
            .field(field1)
            .field_offset(0)
            .build(&mut assembly)
            .unwrap();

        // Offset 4 (typical int alignment)
        let layout2 = FieldLayoutBuilder::new()
            .field(field2)
            .field_offset(4)
            .build(&mut assembly)
            .unwrap();

        // Offset 8 (typical double alignment)
        let layout3 = FieldLayoutBuilder::new()
            .field(field3)
            .field_offset(8)
            .build(&mut assembly)
            .unwrap();

        // Offset 64 (cache line alignment)
        let layout4 = FieldLayoutBuilder::new()
            .field(field4)
            .field_offset(64)
            .build(&mut assembly)
            .unwrap();

        // All should succeed with FieldLayout kind
        assert_eq!(
            layout1.kind(),
            ChangeRefKind::TableRow(TableId::FieldLayout)
        );
        assert_eq!(
            layout2.kind(),
            ChangeRefKind::TableRow(TableId::FieldLayout)
        );
        assert_eq!(
            layout3.kind(),
            ChangeRefKind::TableRow(TableId::FieldLayout)
        );
        assert_eq!(
            layout4.kind(),
            ChangeRefKind::TableRow(TableId::FieldLayout)
        );

        // All should be different references
        assert!(!std::sync::Arc::ptr_eq(&layout1, &layout2));
        assert!(!std::sync::Arc::ptr_eq(&layout1, &layout3));
        assert!(!std::sync::Arc::ptr_eq(&layout1, &layout4));
    }

    #[test]
    fn test_field_layout_builder_union_layout() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Create overlapping fields (union behavior)
        let int_field = 1u32; // Field RID 1
        let float_field = 2u32; // Field RID 2

        // Both fields at offset 0 (overlapping)
        let int_layout = FieldLayoutBuilder::new()
            .field(int_field)
            .field_offset(0)
            .build(&mut assembly)
            .unwrap();

        let float_layout = FieldLayoutBuilder::new()
            .field(float_field)
            .field_offset(0) // Same offset = union
            .build(&mut assembly)
            .unwrap();

        // Both should succeed with different references
        assert!(!std::sync::Arc::ptr_eq(&int_layout, &float_layout));
        assert_eq!(
            int_layout.kind(),
            ChangeRefKind::TableRow(TableId::FieldLayout)
        );
        assert_eq!(
            float_layout.kind(),
            ChangeRefKind::TableRow(TableId::FieldLayout)
        );
    }

    #[test]
    fn test_field_layout_builder_large_offsets() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let field_row = 1u32; // Field RID 1

        // Test large but valid offset
        let large_offset = 1024 * 1024; // 1MB offset
        let layout_ref = FieldLayoutBuilder::new()
            .field(field_row)
            .field_offset(large_offset)
            .build(&mut assembly)
            .unwrap();

        // Should succeed
        assert_eq!(
            layout_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldLayout)
        );
    }

    #[test]
    fn test_field_layout_builder_missing_field_offset() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let field_row = 1u32; // Field RID 1

        let result = FieldLayoutBuilder::new()
            .field(field_row)
            // Missing field_offset
            .build(&mut assembly);

        // Should fail because field offset is required
        assert!(result.is_err());
    }

    #[test]
    fn test_field_layout_builder_missing_field() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let result = FieldLayoutBuilder::new()
            .field_offset(4)
            // Missing field
            .build(&mut assembly);

        // Should fail because field is required
        assert!(result.is_err());
    }

    #[test]
    fn test_field_layout_builder_zero_field_rid() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Use row index 0 (invalid)
        let invalid_field = 0u32;

        let result = FieldLayoutBuilder::new()
            .field(invalid_field)
            .field_offset(0)
            .build(&mut assembly);

        // Should fail because field row index cannot be 0
        assert!(result.is_err());
    }

    #[test]
    fn test_field_layout_builder_reserved_offset() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let field_row = 1u32; // Field RID 1

        let result = FieldLayoutBuilder::new()
            .field(field_row)
            .field_offset(u32::MAX) // Reserved value
            .build(&mut assembly);

        // Should fail because 0xFFFFFFFF is reserved
        assert!(result.is_err());
    }

    #[test]
    fn test_field_layout_builder_multiple_layouts() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Create layouts for multiple fields simulating a struct
        let field1 = 1u32; // int field
        let field2 = 2u32; // float field
        let field3 = 3u32; // double field
        let field4 = 4u32; // byte field

        let layout1 = FieldLayoutBuilder::new()
            .field(field1)
            .field_offset(0) // int at offset 0
            .build(&mut assembly)
            .unwrap();

        let layout2 = FieldLayoutBuilder::new()
            .field(field2)
            .field_offset(4) // float at offset 4
            .build(&mut assembly)
            .unwrap();

        let layout3 = FieldLayoutBuilder::new()
            .field(field3)
            .field_offset(8) // double at offset 8 (aligned)
            .build(&mut assembly)
            .unwrap();

        let layout4 = FieldLayoutBuilder::new()
            .field(field4)
            .field_offset(16) // byte at offset 16
            .build(&mut assembly)
            .unwrap();

        // All should succeed and be different references
        assert!(!std::sync::Arc::ptr_eq(&layout1, &layout2));
        assert!(!std::sync::Arc::ptr_eq(&layout1, &layout3));
        assert!(!std::sync::Arc::ptr_eq(&layout1, &layout4));
        assert!(!std::sync::Arc::ptr_eq(&layout2, &layout3));
        assert!(!std::sync::Arc::ptr_eq(&layout2, &layout4));
        assert!(!std::sync::Arc::ptr_eq(&layout3, &layout4));

        // All should have FieldLayout kind
        assert_eq!(
            layout1.kind(),
            ChangeRefKind::TableRow(TableId::FieldLayout)
        );
        assert_eq!(
            layout2.kind(),
            ChangeRefKind::TableRow(TableId::FieldLayout)
        );
        assert_eq!(
            layout3.kind(),
            ChangeRefKind::TableRow(TableId::FieldLayout)
        );
        assert_eq!(
            layout4.kind(),
            ChangeRefKind::TableRow(TableId::FieldLayout)
        );
    }

    #[test]
    fn test_field_layout_builder_realistic_struct() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Realistic scenario: Point3D struct with explicit layout
        // struct Point3D { float x, y, z; int flags; }
        let x_field = 1u32; // x coordinate
        let y_field = 2u32; // y coordinate
        let z_field = 3u32; // z coordinate
        let flags_field = 4u32; // flags

        // Create layouts with proper float alignment
        let x_layout_ref = FieldLayoutBuilder::new()
            .field(x_field)
            .field_offset(0) // x at start
            .build(&mut assembly)
            .unwrap();

        let y_layout_ref = FieldLayoutBuilder::new()
            .field(y_field)
            .field_offset(4) // y after x (4-byte float)
            .build(&mut assembly)
            .unwrap();

        let z_layout_ref = FieldLayoutBuilder::new()
            .field(z_field)
            .field_offset(8) // z after y (4-byte float)
            .build(&mut assembly)
            .unwrap();

        let flags_layout_ref = FieldLayoutBuilder::new()
            .field(flags_field)
            .field_offset(12) // flags after z (4-byte float)
            .build(&mut assembly)
            .unwrap();

        // All layouts should be created successfully
        assert_eq!(
            x_layout_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldLayout)
        );
        assert_eq!(
            y_layout_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldLayout)
        );
        assert_eq!(
            z_layout_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldLayout)
        );
        assert_eq!(
            flags_layout_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldLayout)
        );

        // All should be different references
        assert!(!std::sync::Arc::ptr_eq(&x_layout_ref, &y_layout_ref));
        assert!(!std::sync::Arc::ptr_eq(&x_layout_ref, &z_layout_ref));
        assert!(!std::sync::Arc::ptr_eq(&x_layout_ref, &flags_layout_ref));
        assert!(!std::sync::Arc::ptr_eq(&y_layout_ref, &z_layout_ref));
        assert!(!std::sync::Arc::ptr_eq(&y_layout_ref, &flags_layout_ref));
        assert!(!std::sync::Arc::ptr_eq(&z_layout_ref, &flags_layout_ref));
    }

    #[test]
    fn test_field_layout_builder_performance_alignment() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Performance-oriented layout with cache line alignment
        let hot_field = 1u32; // Frequently accessed
        let cold_field = 2u32; // Rarely accessed

        // Hot field at start (cache line 0)
        let hot_layout_ref = FieldLayoutBuilder::new()
            .field(hot_field)
            .field_offset(0)
            .build(&mut assembly)
            .unwrap();

        // Cold field at next cache line boundary (64 bytes)
        let cold_layout_ref = FieldLayoutBuilder::new()
            .field(cold_field)
            .field_offset(64)
            .build(&mut assembly)
            .unwrap();

        // Both should succeed
        assert_eq!(
            hot_layout_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldLayout)
        );
        assert_eq!(
            cold_layout_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldLayout)
        );
        assert!(!std::sync::Arc::ptr_eq(&hot_layout_ref, &cold_layout_ref));
    }
}

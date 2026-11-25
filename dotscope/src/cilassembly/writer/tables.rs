//! Table row writer with placeholder resolution.
//!
//! This module provides functionality to resolve placeholder values in metadata table
//! rows before serialization. Placeholders are temporary values (with high bit set)
//! that are replaced with actual heap offsets, tokens, or RIDs when the referenced
//! content is written.
//!
//! # Architecture
//!
//! Placeholder resolution works at the row level before serialization:
//!
//! 1. User adds heap entry via `HeapChanges::append()`, gets `ChangeRefRc`
//! 2. User stores `placeholder()` value in raw row field (e.g., `type_name`)
//! 3. Before writing, heap writer writes content and resolves `ChangeRefRc`
//! 4. `resolve_row_placeholders()` is called to update row fields
//! 5. Standard `RowWritable::row_write()` serializes the resolved row
//!
//! # Field Types That Can Hold Placeholders
//!
//! - **String heap refs**: `type_name`, `name`, `namespace`, etc.
//! - **Blob heap refs**: `signature`, `value`, etc.
//! - **GUID heap refs**: `mvid`, `enc_id`, etc.
//! - **User string heap refs**: (typically in IL, not table rows)
//! - **Coded index refs**: `resolution_scope`, `extends`, `parent`, etc.
//! - **Table index refs**: `field_list`, `method_list`, etc.
//!
//! For coded indices and table indices, the placeholder is stored in the `row` field
//! of the `CodedIndex` struct or directly as a u32 table index. These are resolved
//! to actual RIDs by looking up the ChangeRef's resolved token.

use crate::{
    cilassembly::{changes::ChangeRef, AssemblyChanges},
    metadata::tables::{
        AssemblyRaw, AssemblyRefOsRaw, AssemblyRefProcessorRaw, AssemblyRefRaw, ClassLayoutRaw,
        CodedIndex, ConstantRaw, CustomAttributeRaw, CustomDebugInformationRaw, DeclSecurityRaw,
        DocumentRaw, EventMapRaw, EventPtrRaw, EventRaw, ExportedTypeRaw, FieldLayoutRaw,
        FieldMarshalRaw, FieldPtrRaw, FieldRaw, FieldRvaRaw, FileRaw, GenericParamConstraintRaw,
        GenericParamRaw, ImplMapRaw, ImportScopeRaw, InterfaceImplRaw, LocalConstantRaw,
        LocalScopeRaw, LocalVariableRaw, ManifestResourceRaw, MemberRefRaw,
        MethodDebugInformationRaw, MethodDefRaw, MethodImplRaw, MethodPtrRaw, MethodSemanticsRaw,
        MethodSpecRaw, ModuleRaw, ModuleRefRaw, NestedClassRaw, ParamPtrRaw, ParamRaw,
        PropertyMapRaw, PropertyPtrRaw, PropertyRaw, StandAloneSigRaw, StateMachineMethodRaw,
        TableId, TypeDefRaw, TypeRefRaw, TypeSpecRaw,
    },
};

/// Resolves a potential placeholder value to its actual heap offset.
///
/// If the value has the placeholder flag set (high bit), looks up the
/// corresponding `ChangeRef` and returns its resolved offset. Otherwise
/// returns the original value unchanged.
///
/// # Arguments
///
/// * `value` - The potentially-placeholder value
/// * `changes` - AssemblyChanges for looking up `ChangeRef` by placeholder ID
///
/// # Returns
///
/// The resolved value (actual heap offset) or original value if not a placeholder.
#[inline]
pub fn resolve_placeholder(value: u32, changes: &AssemblyChanges) -> u32 {
    if ChangeRef::is_heap_placeholder(value) {
        if let Some(change_ref) = changes.lookup_by_placeholder(value) {
            if let Some(resolved) = change_ref.offset() {
                return resolved;
            }
        }
    }
    value
}

/// Resolves a potential placeholder value to its actual table row ID.
///
/// If the value has the placeholder flag set (high bit), looks up the
/// corresponding `ChangeRef` and returns the RID from its resolved token.
/// Otherwise returns the original value unchanged.
///
/// This is used for table index fields (like `field_list`, `method_list`)
/// and for the `row` field of `CodedIndex` structures.
///
/// # Arguments
///
/// * `value` - The potentially-placeholder row value
/// * `changes` - AssemblyChanges for looking up `ChangeRef` by placeholder ID
///
/// # Returns
///
/// The resolved RID or original value if not a placeholder.
#[inline]
pub fn resolve_rid_placeholder(value: u32, changes: &AssemblyChanges) -> u32 {
    if ChangeRef::is_placeholder(value) {
        if let Some(change_ref) = changes.lookup_by_placeholder(value) {
            if let Some(token) = change_ref.token() {
                return token.row();
            }
        }
    }
    value
}

/// Resolves placeholders in a `CodedIndex` structure.
///
/// If the `row` field of the coded index contains a placeholder, resolves it
/// to the actual RID from the corresponding `ChangeRef`. The `tag` and `ci_type`
/// fields are preserved.
///
/// # Arguments
///
/// * `coded_index` - The coded index to resolve
/// * `changes` - AssemblyChanges for looking up `ChangeRef` by placeholder ID
#[inline]
pub fn resolve_coded_index_placeholder(coded_index: &mut CodedIndex, changes: &AssemblyChanges) {
    coded_index.row = resolve_rid_placeholder(coded_index.row, changes);
    // Note: The token field of CodedIndex is recomputed during serialization
    // based on tag and row, so we don't need to update it here.
}

/// Trait for resolving placeholders in table row heap reference fields.
///
/// Each table type implements this to resolve its specific heap reference fields.
/// This is called after heap writers have resolved all `ChangeRefRc` entries,
/// and before the row is serialized via `RowWritable::row_write()`.
pub trait ResolvePlaceholders {
    /// Resolves all placeholder values in this row's heap reference fields.
    ///
    /// # Arguments
    ///
    /// * `changes` - AssemblyChanges containing resolved `ChangeRefRc` entries
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges);
}

impl ResolvePlaceholders for ModuleRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // String heap refs
        self.name = resolve_placeholder(self.name, changes);
        // GUID heap refs (stored as 1-based index, but placeholder mechanism works the same)
        self.mvid = resolve_placeholder(self.mvid, changes);
        self.encid = resolve_placeholder(self.encid, changes);
        self.encbaseid = resolve_placeholder(self.encbaseid, changes);
    }
}

impl ResolvePlaceholders for TypeRefRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // String heap refs
        self.type_name = resolve_placeholder(self.type_name, changes);
        self.type_namespace = resolve_placeholder(self.type_namespace, changes);
        // CodedIndex ref
        resolve_coded_index_placeholder(&mut self.resolution_scope, changes);
    }
}

impl ResolvePlaceholders for TypeDefRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // String heap refs
        self.type_name = resolve_placeholder(self.type_name, changes);
        self.type_namespace = resolve_placeholder(self.type_namespace, changes);
        // CodedIndex ref
        resolve_coded_index_placeholder(&mut self.extends, changes);
        // Table index refs
        self.field_list = resolve_rid_placeholder(self.field_list, changes);
        self.method_list = resolve_rid_placeholder(self.method_list, changes);
    }
}

impl ResolvePlaceholders for FieldRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // String heap ref
        self.name = resolve_placeholder(self.name, changes);
        // Blob heap ref
        self.signature = resolve_placeholder(self.signature, changes);
    }
}

impl ResolvePlaceholders for MethodDefRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // String heap ref
        self.name = resolve_placeholder(self.name, changes);
        // Blob heap ref
        self.signature = resolve_placeholder(self.signature, changes);
        // Table index ref
        self.param_list = resolve_rid_placeholder(self.param_list, changes);
        // rva, impl_flags, flags are not heap refs
    }
}

impl ResolvePlaceholders for ParamRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // String heap ref
        self.name = resolve_placeholder(self.name, changes);
        // flags, sequence are not heap refs
    }
}

impl ResolvePlaceholders for InterfaceImplRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Table index ref
        self.class = resolve_rid_placeholder(self.class, changes);
        // CodedIndex ref
        resolve_coded_index_placeholder(&mut self.interface, changes);
    }
}

impl ResolvePlaceholders for MemberRefRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // String heap ref
        self.name = resolve_placeholder(self.name, changes);
        // Blob heap ref
        self.signature = resolve_placeholder(self.signature, changes);
        // CodedIndex ref
        resolve_coded_index_placeholder(&mut self.class, changes);
    }
}

impl ResolvePlaceholders for ConstantRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Blob heap ref
        self.value = resolve_placeholder(self.value, changes);
        // CodedIndex ref
        resolve_coded_index_placeholder(&mut self.parent, changes);
        // constant_type is not a heap ref
    }
}

impl ResolvePlaceholders for CustomAttributeRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Blob heap ref
        self.value = resolve_placeholder(self.value, changes);
        // CodedIndex refs
        resolve_coded_index_placeholder(&mut self.parent, changes);
        resolve_coded_index_placeholder(&mut self.constructor, changes);
    }
}

impl ResolvePlaceholders for FieldMarshalRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Blob heap ref
        self.native_type = resolve_placeholder(self.native_type, changes);
        // CodedIndex ref
        resolve_coded_index_placeholder(&mut self.parent, changes);
    }
}

impl ResolvePlaceholders for DeclSecurityRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Blob heap ref
        self.permission_set = resolve_placeholder(self.permission_set, changes);
        // CodedIndex ref
        resolve_coded_index_placeholder(&mut self.parent, changes);
        // action is not a heap ref
    }
}

impl ResolvePlaceholders for ClassLayoutRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Table index ref
        self.parent = resolve_rid_placeholder(self.parent, changes);
        // packing_size, class_size are not heap refs
    }
}

impl ResolvePlaceholders for FieldLayoutRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Table index ref
        self.field = resolve_rid_placeholder(self.field, changes);
        // field_offset is not a heap ref
    }
}

impl ResolvePlaceholders for StandAloneSigRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Blob heap ref
        self.signature = resolve_placeholder(self.signature, changes);
    }
}

impl ResolvePlaceholders for EventMapRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Table index refs
        self.parent = resolve_rid_placeholder(self.parent, changes);
        self.event_list = resolve_rid_placeholder(self.event_list, changes);
    }
}

impl ResolvePlaceholders for EventRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // String heap ref
        self.name = resolve_placeholder(self.name, changes);
        // CodedIndex ref
        resolve_coded_index_placeholder(&mut self.event_type, changes);
        // event_flags is not a heap ref
    }
}

impl ResolvePlaceholders for PropertyMapRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Table index refs
        self.parent = resolve_rid_placeholder(self.parent, changes);
        self.property_list = resolve_rid_placeholder(self.property_list, changes);
    }
}

impl ResolvePlaceholders for PropertyRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // String heap ref
        self.name = resolve_placeholder(self.name, changes);
        // Blob heap ref (signature field contains the property type signature)
        self.signature = resolve_placeholder(self.signature, changes);
        // flags is not a heap ref
    }
}

impl ResolvePlaceholders for MethodSemanticsRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Table index ref
        self.method = resolve_rid_placeholder(self.method, changes);
        // CodedIndex ref
        resolve_coded_index_placeholder(&mut self.association, changes);
        // semantics is not a heap ref
    }
}

impl ResolvePlaceholders for MethodImplRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Table index ref
        self.class = resolve_rid_placeholder(self.class, changes);
        // CodedIndex refs
        resolve_coded_index_placeholder(&mut self.method_body, changes);
        resolve_coded_index_placeholder(&mut self.method_declaration, changes);
    }
}

impl ResolvePlaceholders for ModuleRefRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // String heap ref
        self.name = resolve_placeholder(self.name, changes);
    }
}

impl ResolvePlaceholders for TypeSpecRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Blob heap ref
        self.signature = resolve_placeholder(self.signature, changes);
    }
}

impl ResolvePlaceholders for ImplMapRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // String heap ref
        self.import_name = resolve_placeholder(self.import_name, changes);
        // CodedIndex ref
        resolve_coded_index_placeholder(&mut self.member_forwarded, changes);
        // Table index ref
        self.import_scope = resolve_rid_placeholder(self.import_scope, changes);
        // mapping_flags is not a heap ref
    }
}

impl ResolvePlaceholders for FieldRvaRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Table index ref
        self.field = resolve_rid_placeholder(self.field, changes);
        // rva is not a heap ref
    }
}

impl ResolvePlaceholders for AssemblyRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Blob heap ref
        self.public_key = resolve_placeholder(self.public_key, changes);
        // String heap refs
        self.name = resolve_placeholder(self.name, changes);
        self.culture = resolve_placeholder(self.culture, changes);
        // hash_alg_id, version fields, flags are not heap refs
    }
}

impl ResolvePlaceholders for AssemblyRefRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Blob heap refs
        self.public_key_or_token = resolve_placeholder(self.public_key_or_token, changes);
        self.hash_value = resolve_placeholder(self.hash_value, changes);
        // String heap refs
        self.name = resolve_placeholder(self.name, changes);
        self.culture = resolve_placeholder(self.culture, changes);
        // version fields, flags are not heap refs
    }
}

impl ResolvePlaceholders for FileRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // String heap ref
        self.name = resolve_placeholder(self.name, changes);
        // Blob heap ref
        self.hash_value = resolve_placeholder(self.hash_value, changes);
        // flags is not a heap ref
    }
}

impl ResolvePlaceholders for ExportedTypeRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // String heap refs
        self.name = resolve_placeholder(self.name, changes);
        self.namespace = resolve_placeholder(self.namespace, changes);
        // CodedIndex ref
        resolve_coded_index_placeholder(&mut self.implementation, changes);
        // flags, type_def_id are not heap refs
    }
}

impl ResolvePlaceholders for ManifestResourceRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // String heap ref
        self.name = resolve_placeholder(self.name, changes);
        // CodedIndex ref
        resolve_coded_index_placeholder(&mut self.implementation, changes);
        // offset, flags are not heap refs
    }
}

impl ResolvePlaceholders for NestedClassRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Table index refs
        self.nested_class = resolve_rid_placeholder(self.nested_class, changes);
        self.enclosing_class = resolve_rid_placeholder(self.enclosing_class, changes);
    }
}

impl ResolvePlaceholders for GenericParamRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // String heap ref
        self.name = resolve_placeholder(self.name, changes);
        // CodedIndex ref
        resolve_coded_index_placeholder(&mut self.owner, changes);
        // number, flags are not heap refs
    }
}

impl ResolvePlaceholders for MethodSpecRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Blob heap ref
        self.instantiation = resolve_placeholder(self.instantiation, changes);
        // CodedIndex ref
        resolve_coded_index_placeholder(&mut self.method, changes);
    }
}

impl ResolvePlaceholders for GenericParamConstraintRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Table index ref
        self.owner = resolve_rid_placeholder(self.owner, changes);
        // CodedIndex ref
        resolve_coded_index_placeholder(&mut self.constraint, changes);
    }
}

impl ResolvePlaceholders for FieldPtrRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Table index ref
        self.field = resolve_rid_placeholder(self.field, changes);
    }
}

impl ResolvePlaceholders for MethodPtrRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Table index ref
        self.method = resolve_rid_placeholder(self.method, changes);
    }
}

impl ResolvePlaceholders for ParamPtrRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Table index ref
        self.param = resolve_rid_placeholder(self.param, changes);
    }
}

impl ResolvePlaceholders for EventPtrRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Table index ref
        self.event = resolve_rid_placeholder(self.event, changes);
    }
}

impl ResolvePlaceholders for PropertyPtrRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Table index ref
        self.property = resolve_rid_placeholder(self.property, changes);
    }
}

impl ResolvePlaceholders for AssemblyRefProcessorRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Table index ref
        self.assembly_ref = resolve_rid_placeholder(self.assembly_ref, changes);
    }
}

impl ResolvePlaceholders for AssemblyRefOsRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Table index ref
        self.assembly_ref = resolve_rid_placeholder(self.assembly_ref, changes);
    }
}

impl ResolvePlaceholders for DocumentRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Blob heap refs
        self.name = resolve_placeholder(self.name, changes);
        self.hash = resolve_placeholder(self.hash, changes);
        // GUID heap refs
        self.hash_algorithm = resolve_placeholder(self.hash_algorithm, changes);
        self.language = resolve_placeholder(self.language, changes);
    }
}

impl ResolvePlaceholders for MethodDebugInformationRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Table index ref
        self.document = resolve_rid_placeholder(self.document, changes);
        // Blob heap ref
        self.sequence_points = resolve_placeholder(self.sequence_points, changes);
    }
}

impl ResolvePlaceholders for LocalScopeRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Table index refs
        self.method = resolve_rid_placeholder(self.method, changes);
        self.import_scope = resolve_rid_placeholder(self.import_scope, changes);
        self.variable_list = resolve_rid_placeholder(self.variable_list, changes);
        self.constant_list = resolve_rid_placeholder(self.constant_list, changes);
    }
}

impl ResolvePlaceholders for LocalVariableRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // String heap ref
        self.name = resolve_placeholder(self.name, changes);
    }
}

impl ResolvePlaceholders for LocalConstantRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // String heap ref
        self.name = resolve_placeholder(self.name, changes);
        // Blob heap ref
        self.signature = resolve_placeholder(self.signature, changes);
    }
}

impl ResolvePlaceholders for ImportScopeRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Table index ref
        self.parent = resolve_rid_placeholder(self.parent, changes);
        // Blob heap ref
        self.imports = resolve_placeholder(self.imports, changes);
    }
}

impl ResolvePlaceholders for StateMachineMethodRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // Table index refs
        self.move_next_method = resolve_rid_placeholder(self.move_next_method, changes);
        self.kickoff_method = resolve_rid_placeholder(self.kickoff_method, changes);
    }
}

impl ResolvePlaceholders for CustomDebugInformationRaw {
    fn resolve_placeholders(&mut self, changes: &AssemblyChanges) {
        // CodedIndex ref
        resolve_coded_index_placeholder(&mut self.parent, changes);
        // GUID heap ref
        self.kind = resolve_placeholder(self.kind, changes);
        // Blob heap ref
        self.value = resolve_placeholder(self.value, changes);
    }
}

/// Resolves placeholders in a boxed table row based on its table ID.
///
/// This is a dispatch function that casts the row to the appropriate type
/// and calls its `ResolvePlaceholders` implementation.
///
/// # Arguments
///
/// * `table_id` - The table type
/// * `row` - Mutable reference to the row (must be the correct type for table_id)
/// * `change_mapper` - Mapper containing resolved `ChangeRefRc` entries
///
/// # Safety
///
/// The caller must ensure `row` is actually the correct type for `table_id`.
/// This function uses dynamic dispatch through the trait.
pub fn resolve_row_placeholders_by_table(
    table_id: TableId,
    row: &mut dyn std::any::Any,
    changes: &AssemblyChanges,
) {
    match table_id {
        TableId::Module => {
            if let Some(r) = row.downcast_mut::<ModuleRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::TypeRef => {
            if let Some(r) = row.downcast_mut::<TypeRefRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::TypeDef => {
            if let Some(r) = row.downcast_mut::<TypeDefRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::Field => {
            if let Some(r) = row.downcast_mut::<FieldRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::MethodDef => {
            if let Some(r) = row.downcast_mut::<MethodDefRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::Param => {
            if let Some(r) = row.downcast_mut::<ParamRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::InterfaceImpl => {
            if let Some(r) = row.downcast_mut::<InterfaceImplRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::MemberRef => {
            if let Some(r) = row.downcast_mut::<MemberRefRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::Constant => {
            if let Some(r) = row.downcast_mut::<ConstantRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::CustomAttribute => {
            if let Some(r) = row.downcast_mut::<CustomAttributeRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::FieldMarshal => {
            if let Some(r) = row.downcast_mut::<FieldMarshalRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::DeclSecurity => {
            if let Some(r) = row.downcast_mut::<DeclSecurityRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::ClassLayout => {
            if let Some(r) = row.downcast_mut::<ClassLayoutRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::FieldLayout => {
            if let Some(r) = row.downcast_mut::<FieldLayoutRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::StandAloneSig => {
            if let Some(r) = row.downcast_mut::<StandAloneSigRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::EventMap => {
            if let Some(r) = row.downcast_mut::<EventMapRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::Event => {
            if let Some(r) = row.downcast_mut::<EventRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::PropertyMap => {
            if let Some(r) = row.downcast_mut::<PropertyMapRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::Property => {
            if let Some(r) = row.downcast_mut::<PropertyRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::MethodSemantics => {
            if let Some(r) = row.downcast_mut::<MethodSemanticsRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::MethodImpl => {
            if let Some(r) = row.downcast_mut::<MethodImplRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::ModuleRef => {
            if let Some(r) = row.downcast_mut::<ModuleRefRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::TypeSpec => {
            if let Some(r) = row.downcast_mut::<TypeSpecRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::ImplMap => {
            if let Some(r) = row.downcast_mut::<ImplMapRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::FieldRVA => {
            if let Some(r) = row.downcast_mut::<FieldRvaRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::Assembly => {
            if let Some(r) = row.downcast_mut::<AssemblyRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::AssemblyRef => {
            if let Some(r) = row.downcast_mut::<AssemblyRefRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::File => {
            if let Some(r) = row.downcast_mut::<FileRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::ExportedType => {
            if let Some(r) = row.downcast_mut::<ExportedTypeRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::ManifestResource => {
            if let Some(r) = row.downcast_mut::<ManifestResourceRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::NestedClass => {
            if let Some(r) = row.downcast_mut::<NestedClassRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::GenericParam => {
            if let Some(r) = row.downcast_mut::<GenericParamRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::MethodSpec => {
            if let Some(r) = row.downcast_mut::<MethodSpecRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::GenericParamConstraint => {
            if let Some(r) = row.downcast_mut::<GenericParamConstraintRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::Document => {
            if let Some(r) = row.downcast_mut::<DocumentRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::MethodDebugInformation => {
            if let Some(r) = row.downcast_mut::<MethodDebugInformationRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::LocalScope => {
            if let Some(r) = row.downcast_mut::<LocalScopeRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::LocalVariable => {
            if let Some(r) = row.downcast_mut::<LocalVariableRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::LocalConstant => {
            if let Some(r) = row.downcast_mut::<LocalConstantRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::ImportScope => {
            if let Some(r) = row.downcast_mut::<ImportScopeRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::StateMachineMethod => {
            if let Some(r) = row.downcast_mut::<StateMachineMethodRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        TableId::CustomDebugInformation => {
            if let Some(r) = row.downcast_mut::<CustomDebugInformationRaw>() {
                r.resolve_placeholders(changes);
            }
        }
        // Tables without heap refs or less common tables
        _ => {
            // No resolution needed for pointer tables, ENC tables, etc.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::changes::{AssemblyChanges, ChangeIds, HeapChanges},
        metadata::{
            tables::{CodedIndex, CodedIndexType},
            token::Token,
        },
    };

    #[test]
    fn test_resolve_placeholder_with_match() {
        let mut changes = AssemblyChanges::empty();
        let mut string_changes = HeapChanges::<String>::new_strings(ChangeIds::new());
        let change_ref = string_changes.append("TestString".to_string());
        changes.string_heap_changes = string_changes;

        // Resolve the change ref to a known offset
        change_ref.resolve_to_offset(0x1234);

        // Get placeholder and resolve it
        let placeholder = change_ref.placeholder();
        assert!(ChangeRef::is_placeholder(placeholder));

        let resolved = resolve_placeholder(placeholder, &changes);
        assert_eq!(resolved, 0x1234);
    }

    #[test]
    fn test_resolve_placeholder_without_match() {
        let changes = AssemblyChanges::empty();

        // Non-placeholder value should pass through unchanged
        let regular_value = 0x5678u32;
        assert!(!ChangeRef::is_placeholder(regular_value));
        assert_eq!(resolve_placeholder(regular_value, &changes), regular_value);
    }

    #[test]
    fn test_resolve_typedef_placeholders() {
        let mut changes = AssemblyChanges::empty();
        let mut string_changes = HeapChanges::<String>::new_strings(ChangeIds::new());
        let name_ref = string_changes.append("MyClass".to_string());
        let ns_ref = string_changes.append("MyNamespace".to_string());
        changes.string_heap_changes = string_changes;

        // Resolve the refs
        name_ref.resolve_to_offset(100);
        ns_ref.resolve_to_offset(200);

        // Create a TypeDef row with placeholder values
        let mut row = TypeDefRaw {
            rid: 1,
            token: Token::new(0x02000001),
            offset: 0,
            flags: 0,
            type_name: name_ref.placeholder(),
            type_namespace: ns_ref.placeholder(),
            extends: CodedIndex::null(CodedIndexType::TypeDefOrRef),
            field_list: 1,
            method_list: 1,
        };

        // Verify placeholders are set
        assert!(ChangeRef::is_placeholder(row.type_name));
        assert!(ChangeRef::is_placeholder(row.type_namespace));

        // Resolve placeholders
        row.resolve_placeholders(&changes);

        // Verify resolved values
        assert_eq!(row.type_name, 100);
        assert_eq!(row.type_namespace, 200);
    }

    #[test]
    fn test_resolve_rid_placeholder_passthrough() {
        // Test that non-placeholder RID values pass through unchanged
        let changes = AssemblyChanges::empty();

        // Non-placeholder value should pass through unchanged
        let regular_rid = 42u32;
        assert!(!ChangeRef::is_placeholder(regular_rid));
        assert_eq!(resolve_rid_placeholder(regular_rid, &changes), regular_rid);
    }

    #[test]
    fn test_resolve_coded_index_passthrough() {
        // Test that CodedIndex with non-placeholder row passes through unchanged
        let changes = AssemblyChanges::empty();

        let mut coded_index = CodedIndex::new(TableId::TypeRef, 15, CodedIndexType::TypeDefOrRef);

        // Verify not a placeholder
        assert!(!ChangeRef::is_placeholder(coded_index.row));

        // Resolve should be a no-op
        resolve_coded_index_placeholder(&mut coded_index, &changes);

        // Values should be unchanged
        assert_eq!(coded_index.row, 15);
        assert_eq!(coded_index.tag, TableId::TypeRef);
    }

    #[test]
    fn test_resolve_memberref_heap_placeholders() {
        // Test that MemberRef heap placeholders (name, signature) are resolved
        let mut changes = AssemblyChanges::empty();

        // Create change refs for heap values: an assembly's heaps share its change ids
        let ids = ChangeIds::new();
        let mut string_changes = HeapChanges::<String>::new_strings(ids.clone());
        let name_ref = string_changes.append("TestMethod".to_string());
        changes.string_heap_changes = string_changes;

        let mut blob_changes = HeapChanges::<Vec<u8>>::new_blobs(ids);
        let sig_ref = blob_changes.append(vec![0x00, 0x01, 0x02]);
        changes.blob_heap_changes = blob_changes;

        // Resolve the heap refs
        name_ref.resolve_to_offset(500);
        sig_ref.resolve_to_offset(600);

        // Create a MemberRef row with placeholder values for heaps, but non-placeholder for class
        let mut row = MemberRefRaw {
            rid: 1,
            token: Token::new(0x0A000001),
            offset: 0,
            class: CodedIndex::new(TableId::TypeRef, 7, CodedIndexType::MemberRefParent),
            name: name_ref.placeholder(),
            signature: sig_ref.placeholder(),
        };

        // Verify heap placeholders are set
        assert!(ChangeRef::is_placeholder(row.name));
        assert!(ChangeRef::is_placeholder(row.signature));
        // Class row is not a placeholder
        assert!(!ChangeRef::is_placeholder(row.class.row));

        // Resolve placeholders
        row.resolve_placeholders(&changes);

        // Verify heap values resolved
        assert_eq!(row.name, 500);
        assert_eq!(row.signature, 600);
        // Class row unchanged
        assert_eq!(row.class.row, 7);
        assert_eq!(row.class.tag, TableId::TypeRef);
    }
}

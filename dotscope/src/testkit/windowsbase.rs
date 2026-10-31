use uguid::Guid;

use crate::metadata::{
    cilobject::CilObject,
    cor20header::{Cor20Flags, Cor20Header},
    imports::{ImportContainer, Imports},
    method::MethodMap,
    resources::{Resource, ResourceType, Resources},
    root::{Root, CIL_HEADER_MAGIC},
    streams::TablesHeader,
    tables::{
        AssemblyRaw, AssemblyRefMap, AssemblyRefRaw, ClassLayoutRaw, CodedIndex, CodedIndexType,
        ConstantRaw, CustomAttributeRaw, DeclSecurityRaw, EventMapRaw, EventRaw, ExportedTypeRaw,
        FieldLayoutRaw, FieldMarshalRaw, FieldRaw, FieldRvaRaw, GenericParamConstraintRaw,
        GenericParamRaw, ImplMapRaw, InterfaceImplRaw, ManifestResourceAttributes,
        ManifestResourceRaw, MemberRefRaw, MethodDefRaw, MethodImplRaw, MethodSemanticsRaw,
        MethodSpecRaw, ModuleRaw, ModuleRc, ModuleRefMap, ModuleRefRaw, NestedClassRaw, ParamRaw,
        PropertyMapRaw, PropertyRaw, StandAloneSigRaw, TableId, TypeDefRaw, TypeRefRaw,
        TypeSpecRaw,
    },
    token::Token,
};

/// Verify that the `Assembly` matches the values of 'WindowsBase.dll' on disk
///
/// ## Arguments
/// * 'asm' - The `Assembly` to be tested
pub fn verify_windowsbasedll(asm: &CilObject) {
    verify_cor20(asm.cor20header());
    verify_root(asm.metadata_root());
    verify_tableheader(asm.tables().unwrap());

    // Get a reference to the imports container
    let imports = asm.imports();

    // Pass imports to the verification methods
    verify_refs_assembly(asm.refs_assembly(), imports.cil());
    verify_refs_module(asm.refs_module(), imports.cil());
    verify_module(asm.module().unwrap());
    verify_resource(asm.resources());
    verify_methods(asm.methods());
}

/// Verify that the 'Cor20Header` matches the values of 'WindowsBase.dll' on disk
///
/// ## Arguments
/// * 'cor20' - The `Cor20Header` to be tested
pub fn verify_cor20(cor20: &Cor20Header) {
    assert_eq!(cor20.cb, 0x48);
    assert_eq!(cor20.major_runtime_version, 2);
    assert_eq!(cor20.minor_runtime_version, 5);
    assert_eq!(cor20.meta_data_rva, 0x12E868);
    assert_eq!(cor20.meta_data_size, 0xABB24);
    assert_eq!(
        cor20.flags,
        Cor20Flags::IL_LIBRARY | Cor20Flags::STRONG_NAME_SIGNED
    );
    assert_eq!(cor20.entry_point_token, 0);
    assert_eq!(cor20.resource_rva, 0x3CEF0);
    assert_eq!(cor20.resource_size, 0x10780);
    assert_eq!(cor20.strong_name_signature_rva, 0x1DCB0C);
    assert_eq!(cor20.strong_name_signature_size, 0x80);
    assert_eq!(cor20.code_manager_table_rva, 0);
    assert_eq!(cor20.code_manager_table_size, 0);
    assert_eq!(cor20.vtable_fixups_rva, 0);
    assert_eq!(cor20.vtable_fixups_size, 0);
    assert_eq!(cor20.export_address_table_jmp_rva, 0);
    assert_eq!(cor20.export_address_table_jmp_size, 0);
    assert_eq!(cor20.managed_native_header_rva, 0x1468);
    assert_eq!(cor20.managed_native_header_size, 0xC4);
}

/// Verify that the metadata 'Root' matches the values of 'WindowsBase.dll' on disk
///
/// ## Arguments
/// * 'root' - The `Root` to be tested
pub fn verify_root(root: &Root) {
    assert_eq!(root.signature, CIL_HEADER_MAGIC);
    assert_eq!(root.major_version, 1);
    assert_eq!(root.minor_version, 1);
    assert_eq!(root.version, "v4.0.30319");
    assert_eq!(root.length, 12);
    assert_eq!(root.flags, 0);
    assert_eq!(root.stream_number, 5);

    {
        let stream = &root.stream_headers[0];
        assert_eq!(stream.name, "#~");
        assert_eq!(stream.offset, 0x6C);
        assert_eq!(stream.size, 0x59EB4);
    }

    {
        let stream = &root.stream_headers[1];
        assert_eq!(stream.name, "#Strings");
        assert_eq!(stream.offset, 0x59F20);
        assert_eq!(stream.size, 0x31BD4);
    }

    {
        let stream = &root.stream_headers[2];
        assert_eq!(stream.name, "#US");
        assert_eq!(stream.offset, 0x8BAF4);
        assert_eq!(stream.size, 0xD028);
    }

    {
        let stream = &root.stream_headers[3];
        assert_eq!(stream.name, "#GUID");
        assert_eq!(stream.offset, 0x98B1C);
        assert_eq!(stream.size, 0x10);
    }

    {
        let stream = &root.stream_headers[4];
        assert_eq!(stream.name, "#Blob");
        assert_eq!(stream.offset, 0x98B2C);
        assert_eq!(stream.size, 0x12FF8);
    }
}

/// Verify that the `TableHeader` matches the values of 'WindowsBase.dll' on disk
///
/// ## Arguments
/// * 'header' - The `TablesHeader` to be tested
pub fn verify_tableheader(tables_header: &TablesHeader) {
    assert_eq!(tables_header.major_version, 2);
    assert_eq!(tables_header.minor_version, 0);
    assert_eq!(tables_header.valid, 0x1F893FB7FF57);
    assert_eq!(tables_header.sorted, 0x16003301FA00);
    assert_eq!(tables_header.table_count(), 33);

    match tables_header.table::<ModuleRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 1);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.generation, 0);
            assert_eq!(row.name, 0x1E026);
            assert_eq!(row.mvid, 1);
            assert_eq!(row.encid, 0);
            assert_eq!(row.encbaseid, 0);
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<TypeRefRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 472);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x01000001);
            assert_eq!(
                row.resolution_scope,
                CodedIndex::new(TableId::AssemblyRef, 1, CodedIndexType::ResolutionScope)
            );
            assert_eq!(row.type_name, 0x18C2C);
            assert_eq!(row.type_namespace, 0x277D8);

            let row = module.get(5).unwrap().unwrap();
            assert_eq!(row.rid, 5);
            assert_eq!(row.token.value(), 0x01000005);
            assert_eq!(
                row.resolution_scope,
                CodedIndex::new(TableId::TypeRef, 4, CodedIndexType::ResolutionScope)
            );
            assert_eq!(row.type_name, 0x27A21);
            assert_eq!(row.type_namespace, 0);

            let row = module.get(320).unwrap().unwrap();
            assert_eq!(row.rid, 320);
            assert_eq!(row.token.value(), 0x01000140);
            assert_eq!(
                row.resolution_scope,
                CodedIndex::new(TableId::AssemblyRef, 16, CodedIndexType::ResolutionScope)
            );
            assert_eq!(row.type_name, 0x22D9A);
            assert_eq!(row.type_namespace, 0x1E15D);
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<TypeDefRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 820);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.flags, 0);
            assert_eq!(row.type_name, 0x1495);
            assert_eq!(row.type_namespace, 0);
            assert_eq!(
                row.extends,
                CodedIndex::new(TableId::TypeDef, 0, CodedIndexType::TypeDefOrRef)
            );
            assert_eq!(row.field_list, 1);
            assert_eq!(row.method_list, 1);

            let row = module.get(5).unwrap().unwrap();
            assert_eq!(row.rid, 5);
            assert_eq!(row.flags, 0x100180);
            assert_eq!(row.type_name, 0x26FB4);
            assert_eq!(row.type_namespace, 0xA58);
            assert_eq!(
                row.extends,
                CodedIndex::new(TableId::TypeRef, 29, CodedIndexType::TypeDefOrRef)
            );
            assert_eq!(row.field_list, 0x2C);
            assert_eq!(row.method_list, 1);

            let row = module.get(320).unwrap().unwrap();
            assert_eq!(row.rid, 320);
            assert_eq!(row.flags, 0x100000);
            assert_eq!(row.type_name, 0x1238D);
            assert_eq!(row.type_namespace, 0x2AF5E);
            assert_eq!(
                row.extends,
                CodedIndex::new(TableId::TypeDef, 319, CodedIndexType::TypeDefOrRef)
            );
            assert_eq!(row.field_list, 0xF45);
            assert_eq!(row.method_list, 0xD60);
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<FieldRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 6241);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.flags, 0x8056);
            assert_eq!(row.name, 0x2747E);
            assert_eq!(row.signature, 0x7F1);

            let row = module.get(5).unwrap().unwrap();
            assert_eq!(row.rid, 5);
            assert_eq!(row.flags, 0x8056);
            assert_eq!(row.name, 0x5FD4);
            assert_eq!(row.signature, 0x7F1);

            let row = module.get(320).unwrap().unwrap();
            assert_eq!(row.rid, 320);
            assert_eq!(row.flags, 0x8056);
            assert_eq!(row.name, 0x5B7A);
            assert_eq!(row.signature, 0x477);
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<MethodDefRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 6496);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.rva, 0xEAA84);
            assert_eq!(row.impl_flags, 0);
            assert_eq!(row.flags, 0x93);
            assert_eq!(row.name, 0xDA47);
            assert_eq!(row.signature, 0xB041);
            assert_eq!(row.param_list, 1);

            let row = module.get(5).unwrap().unwrap();
            assert_eq!(row.rid, 5);
            assert_eq!(row.rva, 0xEAB5C);
            assert_eq!(row.impl_flags, 0);
            assert_eq!(row.flags, 0x93);
            assert_eq!(row.name, 0x1A125);
            assert_eq!(row.signature, 0xB041);
            assert_eq!(row.param_list, 9);

            let row = module.get(320).unwrap().unwrap();
            assert_eq!(row.rid, 320);
            assert_eq!(row.rva, 0xEB604);
            assert_eq!(row.impl_flags, 0);
            assert_eq!(row.flags, 0x1886);
            assert_eq!(row.name, 0x26F0B);
            assert_eq!(row.signature, 1);
            assert_eq!(row.param_list, 0x30E);
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<ParamRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 7877);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.flags, 0);
            assert_eq!(row.sequence, 1);
            assert_eq!(row.name, 0x14593);

            let row = module.get(5).unwrap().unwrap();
            assert_eq!(row.rid, 5);
            assert_eq!(row.flags, 0);
            assert_eq!(row.sequence, 1);
            assert_eq!(row.name, 0x16E17);

            let row = module.get(320).unwrap().unwrap();
            assert_eq!(row.rid, 320);
            assert_eq!(row.flags, 0);
            assert_eq!(row.sequence, 3);
            assert_eq!(row.name, 0x19C18);
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<InterfaceImplRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 122);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.class, 0xB);
            assert_eq!(
                row.interface,
                CodedIndex::new(TableId::TypeRef, 64, CodedIndexType::TypeDefOrRef)
            );

            let row = module.get(5).unwrap().unwrap();
            assert_eq!(row.rid, 5);
            assert_eq!(row.class, 0x10);
            assert_eq!(
                row.interface,
                CodedIndex::new(TableId::TypeSpec, 3, CodedIndexType::TypeDefOrRef)
            );

            let row = module.get(100).unwrap().unwrap();
            assert_eq!(row.rid, 100);
            assert_eq!(row.class, 0x308);
            assert_eq!(
                row.interface,
                CodedIndex::new(TableId::TypeRef, 126, CodedIndexType::TypeDefOrRef)
            );
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<MemberRefRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 1762);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(
                row.class,
                CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::MemberRefParent)
            );
            assert_eq!(row.name, 0x26F0B);
            assert_eq!(row.signature, 1);

            let row = module.get(5).unwrap().unwrap();
            assert_eq!(row.rid, 5);
            assert_eq!(
                row.class,
                CodedIndex::new(TableId::TypeRef, 7, CodedIndexType::MemberRefParent)
            );
            assert_eq!(row.name, 0x26F0B);
            assert_eq!(row.signature, 0x10);

            let row = module.get(100).unwrap().unwrap();
            assert_eq!(row.rid, 100);
            assert_eq!(
                row.class,
                CodedIndex::new(TableId::TypeRef, 64, CodedIndexType::MemberRefParent)
            );
            assert_eq!(row.name, 0x17B5F);
            assert_eq!(row.signature, 1);
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<ConstantRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 4213);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.base, 0xE);
            assert_eq!(
                row.parent,
                CodedIndex::new(TableId::Field, 1, CodedIndexType::HasConstant)
            );
            assert_eq!(row.value, 0x3BB9);

            let row = module.get(5).unwrap().unwrap();
            assert_eq!(row.rid, 5);
            assert_eq!(row.base, 0xE);
            assert_eq!(
                row.parent,
                CodedIndex::new(TableId::Field, 5, CodedIndexType::HasConstant)
            );
            assert_eq!(row.value, 0x3C1D);

            let row = module.get(100).unwrap().unwrap();
            assert_eq!(row.rid, 100);
            assert_eq!(row.base, 8);
            assert_eq!(
                row.parent,
                CodedIndex::new(TableId::Field, 106, CodedIndexType::HasConstant)
            );
            assert_eq!(row.value, 0x4114);
        }

        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<CustomAttributeRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 914);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(
                row.parent,
                CodedIndex::new(TableId::Module, 1, CodedIndexType::HasCustomAttribute)
            );
            assert_eq!(
                row.constructor,
                CodedIndex::new(TableId::MemberRef, 23, CodedIndexType::CustomAttributeType)
            );
            assert_eq!(row.value, 0x4015);

            let row = module.get(5).unwrap().unwrap();
            assert_eq!(row.rid, 5);
            assert_eq!(
                row.parent,
                CodedIndex::new(TableId::Assembly, 1, CodedIndexType::HasCustomAttribute)
            );
            assert_eq!(
                row.constructor,
                CodedIndex::new(TableId::MemberRef, 3, CodedIndexType::CustomAttributeType)
            );
            assert_eq!(row.value, 0xFC8F);

            let row = module.get(100).unwrap().unwrap();
            assert_eq!(row.rid, 100);
            assert_eq!(
                row.parent,
                CodedIndex::new(TableId::TypeDef, 81, CodedIndexType::HasCustomAttribute)
            );
            assert_eq!(
                row.constructor,
                CodedIndex::new(
                    TableId::MethodDef,
                    2621,
                    CodedIndexType::CustomAttributeType
                )
            );
            assert_eq!(row.value, 0x4015);
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<FieldMarshalRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 620);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(
                row.parent,
                CodedIndex::new(TableId::Param, 135, CodedIndexType::HasFieldMarshal)
            );
            assert_eq!(row.native_type, 0xA56F);

            let row = module.get(5).unwrap().unwrap();
            assert_eq!(row.rid, 5);
            assert_eq!(
                row.parent,
                CodedIndex::new(TableId::Param, 309, CodedIndexType::HasFieldMarshal)
            );
            assert_eq!(row.native_type, 0xA58F);

            let row = module.get(100).unwrap().unwrap();
            assert_eq!(row.rid, 100);
            assert_eq!(
                row.parent,
                CodedIndex::new(TableId::Field, 4740, CodedIndexType::HasFieldMarshal)
            );
            assert_eq!(row.native_type, 0xA0E9);
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<DeclSecurityRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 1);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.action, 8);
            assert_eq!(
                row.parent,
                CodedIndex::new(TableId::Assembly, 1, CodedIndexType::HasDeclSecurity)
            );
            assert_eq!(row.permission_set, 0xA4C9);
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<ClassLayoutRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 13);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.packing_size, 0);
            assert_eq!(row.class_size, 0x10);
            assert_eq!(row.parent, 0x28);

            let row = module.get(5).unwrap().unwrap();
            assert_eq!(row.rid, 5);
            assert_eq!(row.packing_size, 1);
            assert_eq!(row.class_size, 0);
            assert_eq!(row.parent, 0x24C);

            let row = module.get(10).unwrap().unwrap();
            assert_eq!(row.rid, 10);
            assert_eq!(row.packing_size, 1);
            assert_eq!(row.class_size, 0x34);
            assert_eq!(row.parent, 0x32E);
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<FieldLayoutRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 83);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.field_offset, 0);
            assert_eq!(row.field, 0x808);

            let row = module.get(5).unwrap().unwrap();
            assert_eq!(row.rid, 5);
            assert_eq!(row.field_offset, 0);
            assert_eq!(row.field, 0x9A4);

            let row = module.get(50).unwrap().unwrap();
            assert_eq!(row.rid, 50);
            assert_eq!(row.field_offset, 0);
            assert_eq!(row.field, 0xC74);
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<StandAloneSigRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 668);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.signature, 0x220);

            let row = module.get(5).unwrap().unwrap();
            assert_eq!(row.rid, 5);
            assert_eq!(row.signature, 0x280);

            let row = module.get(100).unwrap().unwrap();
            assert_eq!(row.rid, 100);
            assert_eq!(row.signature, 0xB9D);
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<EventMapRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 18);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.parent, 0xC);
            assert_eq!(row.event_list, 0x1);

            let row = module.get(5).unwrap().unwrap();
            assert_eq!(row.rid, 5);
            assert_eq!(row.parent, 0x120);
            assert_eq!(row.event_list, 5);

            let row = module.get(10).unwrap().unwrap();
            assert_eq!(row.rid, 10);
            assert_eq!(row.parent, 0x158);
            assert_eq!(row.event_list, 0xD);
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<EventRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 47);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.flags, 0);
            assert_eq!(row.name, 0xEF15);
            assert_eq!(
                row.event_type,
                CodedIndex::new(TableId::TypeRef, 69, CodedIndexType::TypeDefOrRef)
            );

            let row = module.get(5).unwrap().unwrap();
            assert_eq!(row.rid, 5);
            assert_eq!(row.flags, 0);
            assert_eq!(row.name, 0x1BBAA);
            assert_eq!(
                row.event_type,
                CodedIndex::new(TableId::TypeDef, 290, CodedIndexType::TypeDefOrRef)
            );

            let row = module.get(25).unwrap().unwrap();
            assert_eq!(row.rid, 25);
            assert_eq!(row.flags, 0);
            assert_eq!(row.name, 0x13403);
            assert_eq!(
                row.event_type,
                CodedIndex::new(TableId::TypeDef, 369, CodedIndexType::TypeDefOrRef)
            );
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<PropertyMapRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 234);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.parent, 0xC);
            assert_eq!(row.property_list, 1);

            let row = module.get(5).unwrap().unwrap();
            assert_eq!(row.rid, 5);
            assert_eq!(row.parent, 0x15);
            assert_eq!(row.property_list, 0xB);

            let row = module.get(100).unwrap().unwrap();
            assert_eq!(row.rid, 100);
            assert_eq!(row.parent, 0x103);
            assert_eq!(row.property_list, 0x36D);
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<PropertyRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 1511);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.flags, 0);
            assert_eq!(row.name, 0x1458B);
            assert_eq!(row.signature, 0xF6F5);

            let row = module.get(5).unwrap().unwrap();
            assert_eq!(row.rid, 5);
            assert_eq!(row.flags, 0);
            assert_eq!(row.name, 0x4494);
            assert_eq!(row.signature, 0xF6FD);

            let row = module.get(100).unwrap().unwrap();
            assert_eq!(row.rid, 100);
            assert_eq!(row.flags, 0);
            assert_eq!(row.name, 0x1EEE3);
            assert_eq!(row.signature, 0xF728);
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<MethodSemanticsRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 1848);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.semantics, 8);
            assert_eq!(row.method, 0x19C);
            assert_eq!(
                row.association,
                CodedIndex::new(TableId::Event, 1, CodedIndexType::HasSemantics)
            );

            let row = module.get(5).unwrap().unwrap();
            assert_eq!(row.rid, 5);
            assert_eq!(row.semantics, 0x10);
            assert_eq!(row.method, 0x336);
            assert_eq!(
                row.association,
                CodedIndex::new(TableId::Event, 2, CodedIndexType::HasSemantics)
            );

            let row = module.get(100).unwrap().unwrap();
            assert_eq!(row.rid, 100);
            assert_eq!(row.semantics, 8);
            assert_eq!(row.method, 0x10FF);
            assert_eq!(
                row.association,
                CodedIndex::new(TableId::Event, 32, CodedIndexType::HasSemantics)
            );
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<MethodImplRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 174);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.class, 0xC);
            assert_eq!(
                row.method_body,
                CodedIndex::new(TableId::MethodDef, 408, CodedIndexType::MethodDefOrRef)
            );
            assert_eq!(
                row.method_declaration,
                CodedIndex::new(TableId::MemberRef, 25, CodedIndexType::MethodDefOrRef)
            );

            let row = module.get(5).unwrap().unwrap();
            assert_eq!(row.rid, 5);
            assert_eq!(row.class, 0x5C);
            assert_eq!(
                row.method_body,
                CodedIndex::new(TableId::MethodDef, 1074, CodedIndexType::MethodDefOrRef)
            );
            assert_eq!(
                row.method_declaration,
                CodedIndex::new(TableId::MemberRef, 40, CodedIndexType::MethodDefOrRef)
            );

            let row = module.get(100).unwrap().unwrap();
            assert_eq!(row.rid, 100);
            assert_eq!(row.class, 0x2E9);
            assert_eq!(
                row.method_body,
                CodedIndex::new(TableId::MethodDef, 6142, CodedIndexType::MethodDefOrRef)
            );
            assert_eq!(
                row.method_declaration,
                CodedIndex::new(TableId::MethodDef, 1822, CodedIndexType::MethodDefOrRef)
            );
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<ModuleRefRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 29);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.name, 0x1E036);

            let row = module.get(5).unwrap().unwrap();
            assert_eq!(row.rid, 5);
            assert_eq!(row.name, 0x1DF93);

            let row = module.get(25).unwrap().unwrap();
            assert_eq!(row.rid, 25);
            assert_eq!(row.name, 0x1E09E);
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<TypeSpecRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 234);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.signature, 0x49);

            let row = module.get(5).unwrap().unwrap();
            assert_eq!(row.rid, 5);
            assert_eq!(row.signature, 0x67);

            let row = module.get(100).unwrap().unwrap();
            assert_eq!(row.rid, 100);
            assert_eq!(row.signature, 0x1418);
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<ImplMapRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 422);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.mapping_flags, 0x147);
            assert_eq!(
                row.member_forwarded,
                CodedIndex::new(TableId::MethodDef, 14, CodedIndexType::MemberForwarded)
            );
            assert_eq!(row.import_name, 0x2A5E1);
            assert_eq!(row.import_scope, 0x2);

            let row = module.get(5).unwrap().unwrap();
            assert_eq!(row.rid, 5);
            assert_eq!(row.mapping_flags, 0x1120);
            assert_eq!(
                row.member_forwarded,
                CodedIndex::new(TableId::MethodDef, 21, CodedIndexType::MemberForwarded)
            );
            assert_eq!(row.import_name, 0x1BAE);
            assert_eq!(row.import_scope, 0x3);

            let row = module.get(100).unwrap().unwrap();
            assert_eq!(row.rid, 100);
            assert_eq!(row.mapping_flags, 0x1166);
            assert_eq!(
                row.member_forwarded,
                CodedIndex::new(TableId::MethodDef, 137, CodedIndexType::MemberForwarded)
            );
            assert_eq!(row.import_name, 0x14090);
            assert_eq!(row.import_scope, 0x5);
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<FieldRvaRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 5);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.rva, 0x3CE40);
            assert_eq!(row.field, 0x119E);

            let row = module.get(5).unwrap().unwrap();
            assert_eq!(row.rid, 5);
            assert_eq!(row.rva, 0x3CED0);
            assert_eq!(row.field, 0x11A2);
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<AssemblyRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 1);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.hash_alg_id, 0x8004);
            assert_eq!(row.major_version, 8);
            assert_eq!(row.minor_version, 0);
            assert_eq!(row.build_number, 0);
            assert_eq!(row.revision_number, 0);
            assert_eq!(row.flags, 1);
            assert_eq!(row.public_key, 0x3B17);
            assert_eq!(row.name, 0x1757F);
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<AssemblyRefRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 32);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.major_version, 8);
            assert_eq!(row.minor_version, 0);
            assert_eq!(row.build_number, 0);
            assert_eq!(row.revision_number, 0);
            assert_eq!(row.flags, 0);
            assert_eq!(row.public_key_or_token, 0x3AF3);
            assert_eq!(row.name, 0x15D67);
            assert_eq!(row.hash_value, 0);

            let row = module.get(5).unwrap().unwrap();
            assert_eq!(row.rid, 5);
            assert_eq!(row.major_version, 8);
            assert_eq!(row.minor_version, 0);
            assert_eq!(row.build_number, 0);
            assert_eq!(row.revision_number, 0);
            assert_eq!(row.flags, 0);
            assert_eq!(row.public_key_or_token, 0x3AF3);
            assert_eq!(row.name, 0x289E2);
            assert_eq!(row.hash_value, 0);

            let row = module.get(25).unwrap().unwrap();
            assert_eq!(row.rid, 25);
            assert_eq!(row.major_version, 8);
            assert_eq!(row.minor_version, 0);
            assert_eq!(row.build_number, 0);
            assert_eq!(row.revision_number, 0);
            assert_eq!(row.flags, 0);
            assert_eq!(row.public_key_or_token, 0x3AF3);
            assert_eq!(row.name, 0x1DB65);
            assert_eq!(row.hash_value, 0);
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<ExportedTypeRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 63);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.flags, 0x200000);
            assert_eq!(row.type_def_id, 0);
            assert_eq!(row.name, 0x692);
            assert_eq!(row.namespace, 0x1DB2B);
            assert_eq!(
                row.implementation,
                CodedIndex::new(TableId::AssemblyRef, 11, CodedIndexType::Implementation)
            );

            let row = module.get(5).unwrap().unwrap();
            assert_eq!(row.rid, 5);
            assert_eq!(row.flags, 0x200000);
            assert_eq!(row.type_def_id, 0);
            assert_eq!(row.name, 0x28F73);
            assert_eq!(row.namespace, 0xFCCD);
            assert_eq!(
                row.implementation,
                CodedIndex::new(TableId::AssemblyRef, 11, CodedIndexType::Implementation)
            );

            let row = module.get(50).unwrap().unwrap();
            assert_eq!(row.rid, 50);
            assert_eq!(row.flags, 0x200000);
            assert_eq!(row.type_def_id, 0);
            assert_eq!(row.name, 0x1881B);
            assert_eq!(row.namespace, 0x23909);
            assert_eq!(
                row.implementation,
                CodedIndex::new(TableId::AssemblyRef, 2, CodedIndexType::Implementation)
            );
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<ManifestResourceRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 1);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.flags, 1);
            assert_eq!(row.name, 0x279FC);
            assert_eq!(
                row.implementation,
                CodedIndex::new(TableId::File, 0, CodedIndexType::Implementation)
            );
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<NestedClassRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 379);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.nested_class, 0x1BA);
            assert_eq!(row.enclosing_class, 2);

            let row = module.get(5).unwrap().unwrap();
            assert_eq!(row.rid, 5);
            assert_eq!(row.nested_class, 0x1BE);
            assert_eq!(row.enclosing_class, 6);

            let row = module.get(50).unwrap().unwrap();
            assert_eq!(row.rid, 50);
            assert_eq!(row.nested_class, 0x1EB);
            assert_eq!(row.enclosing_class, 6);
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<GenericParamRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 60);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.number, 0);
            assert_eq!(row.flags, 0);
            assert_eq!(
                row.owner,
                CodedIndex::new(TableId::TypeDef, 19, CodedIndexType::TypeOrMethodDef)
            );
            assert_eq!(row.name, 0xB6F1);

            let row = module.get(5).unwrap().unwrap();
            assert_eq!(row.rid, 5);
            assert_eq!(row.number, 0);
            assert_eq!(row.flags, 0);
            assert_eq!(
                row.owner,
                CodedIndex::new(TableId::TypeDef, 23, CodedIndexType::TypeOrMethodDef)
            );
            assert_eq!(row.name, 0xB6F1);

            let row = module.get(50).unwrap().unwrap();
            assert_eq!(row.rid, 50);
            assert_eq!(row.number, 0);
            assert_eq!(row.flags, 0);
            assert_eq!(
                row.owner,
                CodedIndex::new(TableId::MethodDef, 1031, CodedIndexType::TypeOrMethodDef)
            );
            assert_eq!(row.name, 0xB6F1);
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<MethodSpecRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 37);

            let row = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(
                row.method,
                CodedIndex::new(TableId::MemberRef, 160, CodedIndexType::MethodDefOrRef)
            );
            assert_eq!(row.instantiation, 0x343);

            let row = module.get(5).unwrap().unwrap();
            assert_eq!(row.rid, 5);
            assert_eq!(
                row.method,
                CodedIndex::new(TableId::MemberRef, 249, CodedIndexType::MethodDefOrRef)
            );
            assert_eq!(row.instantiation, 0x50C);

            let row = module.get(25).unwrap().unwrap();
            assert_eq!(row.rid, 25);
            assert_eq!(
                row.method,
                CodedIndex::new(TableId::MemberRef, 1281, CodedIndexType::MethodDefOrRef)
            );
            assert_eq!(row.instantiation, 0x2A34);
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<GenericParamConstraintRaw>() {
        Some(module) => {
            assert_eq!(module.row_count, 3);

            let row: GenericParamConstraintRaw = module.get(1).unwrap().unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.owner, 0x11);
            assert_eq!(
                row.constraint,
                CodedIndex::new(TableId::TypeRef, 73, CodedIndexType::TypeDefOrRef)
            );

            let row = module.get(3).unwrap().unwrap();
            assert_eq!(row.rid, 3);
            assert_eq!(row.owner, 0x32);
            assert_eq!(
                row.constraint,
                CodedIndex::new(TableId::TypeRef, 64, CodedIndexType::TypeDefOrRef)
            );
        }
        None => {
            panic!("This tables should be there");
        }
    }
}

/// Verify that the `AssemblyRef` table has been parsed properly, and the reconstructed metadata matches
///
/// ## Arguments
/// * 'assembly_refs' - The `AssemblyRefs` to be tested
/// * 'imports' - The `Imports` container
pub fn verify_refs_assembly(asm_refs: &AssemblyRefMap, imports: &Imports) {
    assert_eq!(asm_refs.len(), 32);

    let m1 = asm_refs.get(&Token::new(0x23000001)).unwrap();
    let m11 = asm_refs
        .iter()
        .find(|entry| entry.value().name == "System.Runtime")
        .unwrap();
    assert_eq!(m1.value().name, m11.value().name);

    // Get imports using the ImportContainer trait
    let m1_imports = m1.value().get_imports(imports);
    let m11_imports = m11.value().get_imports(imports);
    assert_eq!(m1_imports.len(), m11_imports.len());

    // Verify expected imports exist by fullname lookup
    assert!(imports
        .by_fullname("System.Runtime.InteropServices.GCHandle")
        .is_some());
    assert!(imports
        .by_fullname("System.Runtime.CompilerServices.FixedBufferAttribute")
        .is_some());
    assert!(imports
        .by_fullname("System.Runtime.Versioning.TargetFrameworkAttribute")
        .is_some());

    let m2 = asm_refs.get(&Token::new(0x2300001E)).unwrap();
    let m22 = asm_refs
        .iter()
        .find(|entry| entry.value().name == "System.Linq")
        .unwrap();
    assert_eq!(m2.value().name, m22.value().name);

    // Get imports using the ImportContainer trait
    let m2_imports = m2.value().get_imports(imports);
    let m22_imports = m22.value().get_imports(imports);
    assert_eq!(m2_imports.len(), m22_imports.len());

    // Verify expected imports exist
    assert!(imports.by_fullname("System.Linq.Enumerable").is_some());
    assert!(imports
        .by_fullname("System.Linq.IOrderedEnumerable`1")
        .is_some());
}

/// Verify that the `ModuleRef` table has been parsed properly, and the reconstructed metadata matches
///
/// ## Arguments
/// * 'module_refs' - The `ModuleRefs` to be tested
/// * 'imports' - The `Imports` container
pub fn verify_refs_module(modules: &ModuleRefMap, imports: &Imports) {
    assert_eq!(modules.len(), 29);

    let gdi = modules
        .iter()
        .find(|entry| entry.value().name == "gdi32.dll")
        .unwrap();
    let gdi2 = modules.get(&Token::new(0x1A000002)).unwrap();
    assert_eq!(gdi.value().name, gdi2.value().name);

    // Get imports using the ImportContainer trait
    let gdi_imports = gdi.value().get_imports(imports);
    let gdi2_imports = gdi2.value().get_imports(imports);
    assert_eq!(gdi_imports.len(), gdi2_imports.len());

    // Verify expected method imports exist
    assert!(imports.by_name("SetEnhMetaFileBits").is_some());
    assert!(imports.by_name("EndDoc").is_some());
    assert!(imports.by_name("CreateCompatibleBitmap").is_some());
    assert!(imports.by_name("SelectObject").is_some());
    assert!(imports.by_name("GetStockObject").is_some());

    let kernel32 = modules
        .iter()
        .find(|entry| entry.value().name == "kernel32.dll")
        .unwrap();
    let kernel322 = modules.get(&Token::new(0x1A000005)).unwrap();
    assert_eq!(kernel32.value().name, kernel322.value().name);

    // Get imports using the ImportContainer trait
    let kernel32_imports = kernel32.value().get_imports(imports);
    let kernel322_imports = kernel322.value().get_imports(imports);
    assert_eq!(kernel32_imports.len(), kernel322_imports.len());

    // Verify expected method imports exist
    assert!(imports.by_name("GetCurrentThread").is_some());
    assert!(imports.by_name("OpenProcess").is_some());
    assert!(imports.by_name("RtlMoveMemory").is_some());
    assert!(imports.by_name("GetModuleFileName").is_some());
    assert!(imports.by_name("CloseHandle").is_some());

    let ntdll = modules
        .iter()
        .find(|entry| entry.value().name == "ntdll.dll")
        .unwrap();
    let ntdll2 = modules.get(&Token::new(0x1A000015)).unwrap();
    assert_eq!(ntdll.value().name, ntdll2.value().name);

    // Get imports using the ImportContainer trait
    let ntdll_imports = ntdll.value().get_imports(imports);
    let ntdll2_imports = ntdll2.value().get_imports(imports);
    assert_eq!(ntdll_imports.len(), ntdll2_imports.len());

    // Verify expected method imports exist
    assert!(imports.by_name("RtlNtStatusToDosError").is_some());

    let pn3 = modules
        .iter()
        .find(|entry| entry.value().name == "PresentationNative_cor3.dll")
        .unwrap();
    let pn32 = modules.get(&Token::new(0x1A00001D)).unwrap();
    assert_eq!(pn3.value().name, pn32.value().name);

    // Get imports using the ImportContainer trait
    let pn3_imports = pn3.value().get_imports(imports);
    let pn32_imports = pn32.value().get_imports(imports);
    assert_eq!(pn3_imports.len(), pn32_imports.len());

    // Verify expected method imports exist
    assert!(imports.by_name("SetWindowLongWrapper").is_some());
    assert!(imports.by_name("GetWindowLongWrapper").is_some());
    assert!(imports.by_name("GetParentWrapper").is_some());
    assert!(imports.by_name("IsWindowsVistaOrGreater").is_some());
    assert!(imports.by_name("EnableWindowWrapper").is_some());
}

/// Verify that the `Module` has been parsed properly, and the reconstructed metadata matches
///
/// ## Arguments
/// * 'module' - The `Module` to be tested
pub fn verify_module(module: &ModuleRc) {
    assert_eq!(module.generation, 0);
    assert_eq!(module.name, "WindowsBase.dll");
    assert_eq!(
        module.mvid,
        Guid::parse_or_panic("5a399934-C979-4BE6-AFCB-5414C3F92F00")
    );
}

/// Verify that the `Module` has been parsed properly, and the reconstructed metadata matches
///
/// ## Arguments
/// * 'res' - The `Resource` to be tested
pub fn verify_resource(res: &Resources) {
    assert_eq!(res.len(), 1);

    let resource = res.get("FxResources.WindowsBase.SR.resources").unwrap();
    assert_eq!(resource.flags, ManifestResourceAttributes::PUBLIC);
    assert!(resource.source.is_none());

    let data = res.get_data(&resource).unwrap();
    assert_eq!(data.len(), 67451);

    verify_wbdll_resource_buffer(data);
}

/// Verify that the passed buffer matches the expected resources from WindowsBase.dll
///
/// This function handles two cases:
/// 1. Raw data with 4-byte length prefix (from .bin files or old API)
/// 2. Data without length prefix (from new `get_data()` API)
///
/// ## Arguments
/// * 'data' - The resource buffer
pub fn verify_wbdll_resource_buffer(data: &[u8]) {
    // Detect if data starts with 4-byte length prefix by checking if data[0..4]
    // equals the length of the rest of the data (or close to it)
    let has_length_prefix = if data.len() >= 4 {
        let prefix_value = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        // Allow 1 byte tolerance for padding
        prefix_value >= data.len() - 5 && prefix_value <= data.len() - 4
    } else {
        false
    };

    // Skip the length prefix if present
    let actual_data = if has_length_prefix { &data[4..] } else { data };

    let mut resource = Resource::parse(actual_data).unwrap();
    assert_eq!(resource.res_mgr_header_version, 1);
    assert_eq!(resource.header_size, 0x91);
    assert_eq!(resource.reader_type, "System.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089");
    assert_eq!(
        resource.resource_set_type,
        "System.Resources.RuntimeResourceSet"
    );
    // rr_header_offset is calculated as parser position in the buffer.
    // Value is 0x9D (157) for data without length prefix
    assert_eq!(resource.rr_header_offset, 0x9D);
    assert_eq!(resource.rr_version, 2);
    assert_eq!(resource.resource_count, 0x232);
    assert_eq!(resource.type_names.len(), 0);
    assert_eq!(resource.padding, 7);
    assert_eq!(resource.name_hashes.len(), 562);
    assert_eq!(resource.name_positions.len(), 562);
    // These values are stored in the file
    assert_eq!(resource.data_section_offset, 0x8F88);
    assert_eq!(resource.name_section_offset, 0x1244);
    assert!(!resource.is_debug);

    let parsed = resource.read_resources(actual_data).unwrap();
    let buffertoosmall = parsed.get("BufferTooSmall").unwrap();
    assert_eq!(buffertoosmall.name, "BufferTooSmall");
    assert_eq!(buffertoosmall.name_hash, 0x148859CE);
    match &buffertoosmall.data {
        ResourceType::String(str) => assert_eq!(
            str,
            "Buffer is too small to accommodate the specified parameters."
        ),
        _ => panic!("Wrong resource type for BufferTooSmall"),
    }
}

/// Verify that certain methods from WindowsBase.dll are processed correctly
///
/// ## Arguments
/// * 'methods' - All methods that have been found
pub fn verify_methods(methods: &MethodMap) {
    assert_eq!(methods.len(), 6496);

    let search = methods.get(&Token::new(0x6000280)).unwrap();
    let fn_search = search.value();
    assert_eq!(fn_search.name, "Search");
    assert_eq!(fn_search.rva, Some(0xF10FC));
    assert!(fn_search.is_code_il());
    assert_eq!(fn_search.block_count(), 4);
    assert_eq!(fn_search.body.get().unwrap().max_stack, 3);
    assert_eq!(fn_search.local_vars.count(), 1);
}

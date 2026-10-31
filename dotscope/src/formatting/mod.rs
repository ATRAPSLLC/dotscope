//! ILDasm-compatible CIL disassembly formatter.
//!
//! This module provides a comprehensive formatter that produces ILDasm/ILAsm-compatible
//! text output from .NET assembly metadata. [`crate::formatting::IlFormatter`] is the main
//! entry point, with [`crate::formatting::FormatterOptions`] controlling the level of detail
//! in the output.
//!
//! # Usage
//!
//! ```rust,no_run
//! use dotscope::formatting::{IlFormatter, FormatterOptions};
//! use dotscope::CilObject;
//!
//! let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
//! let formatter = IlFormatter::new(FormatterOptions::default());
//!
//! let mut output = Vec::new();
//! formatter.format_assembly(&mut output, &assembly)?;
//! # Ok::<(), dotscope::Error>(())
//! ```

mod assembly;
mod attributes;
mod events;
mod exceptions;
mod fields;
mod generics;
mod method_body;
mod methods;
mod properties;
mod resources;
mod security;
mod tokens;
mod types;
mod vtfixup;

mod helpers;

use std::io::{self, Write};

use crate::{
    formatting::{
        helpers::{assembly_scoped_name, format_constant, quote_identifier},
        tokens::{resolve_declaring_type, resolve_token},
    },
    metadata::{
        method::Method,
        tables::{ParamAttributes, TableId},
        typesystem::{CilType, CilTypeReference},
        vtfixup::{parse, VtFixupContext},
    },
    CilObject,
};

/// Display options for ILDasm-compatible CIL disassembly output.
pub struct FormatterOptions {
    /// Show hex dump of instruction encoding (`--bytes`).
    pub show_bytes: bool,
    /// Show metadata token comments (`--tokens`).
    pub show_tokens: bool,
    /// Show `IL_XXXX` offset labels (default: `true`).
    pub show_offsets: bool,
    /// Suppress assembly/module header.
    pub no_header: bool,
    /// Raw instruction stream only.
    pub raw: bool,
    /// Use assembly-qualified names like `[mscorlib]System.Object` (default: `true`).
    pub assembly_qualified_names: bool,
    /// Show `.custom` attribute directives (default: `true`).
    pub show_custom_attributes: bool,
    /// Show `.permissionset` directives (default: `true`).
    pub show_security: bool,
    /// Show `Method begins at RVA` / `Code size` comments.
    pub show_rva_comments: bool,
}

impl Default for FormatterOptions {
    fn default() -> Self {
        Self {
            show_bytes: false,
            show_tokens: false,
            show_offsets: true,
            no_header: false,
            raw: false,
            assembly_qualified_names: true,
            show_custom_attributes: true,
            show_security: true,
            show_rva_comments: false,
        }
    }
}

/// ILDasm-compatible CIL disassembly formatter.
///
/// Produces text output matching the style of Microsoft's ILDasm tool.
/// Construct via [`IlFormatter::new`] with a [`FormatterOptions`] configuration.
pub struct IlFormatter {
    opts: FormatterOptions,
}

impl IlFormatter {
    /// Create a new formatter with the given options.
    #[must_use]
    pub fn new(opts: FormatterOptions) -> Self {
        Self { opts }
    }

    /// Returns a reference to the formatter options.
    #[must_use]
    pub fn options(&self) -> &FormatterOptions {
        &self.opts
    }

    /// Format the full assembly: header, assembly extern refs, types, and methods.
    pub fn format_assembly(&self, w: &mut dyn Write, asm: &CilObject) -> io::Result<()> {
        let vtfixup_ctx = parse(asm);

        if !self.opts.no_header && !self.opts.raw {
            assembly::format_assembly_refs(w, asm)?;
            assembly::format_module_refs(w, asm)?;
            assembly::format_header(&self.opts, w, asm)?;
            assembly::format_file_directives(w, asm)?;
            assembly::format_exported_types(&self.opts, w, asm)?;
            assembly::format_data_directives(w, asm)?;

            if let Some(ref ctx) = vtfixup_ctx {
                vtfixup::format_vtfixup_directives(w, ctx, asm.file().sections())?;
                writeln!(w)?;
            }

            resources::format_resources(w, asm)?;
        }

        let entry_point_token = asm.cor20header().entry_point_token;

        let all_types = asm
            .query_types()
            .filter(|t| t.token.is_table(TableId::TypeDef))
            .filter(|t| t.name != "<Module>" || !t.methods.is_empty())
            .find_all();

        for cil_type in &all_types {
            // Skip nested types at the top level — they are emitted inside their
            // enclosing type's class body by format_type().
            if cil_type.enclosing_type().is_some() {
                continue;
            }
            self.format_type(w, cil_type, asm, entry_point_token, vtfixup_ctx.as_ref())?;
        }

        Ok(())
    }

    /// Format a single type: class header, methods, closing brace.
    pub fn format_type(
        &self,
        w: &mut dyn Write,
        cil_type: &CilType,
        asm: &CilObject,
        entry_point_token: u32,
        vtfixup_ctx: Option<&VtFixupContext>,
    ) -> io::Result<()> {
        if !self.opts.raw {
            types::format_type_begin(w, cil_type, asm)?;

            if self.opts.show_custom_attributes {
                attributes::format_custom_attributes(w, &cil_type.custom_attributes, "  ", asm)?;
            }

            // .interfaceimpl custom attributes (ILDasm order: after type CAs, before generic param CAs)
            if self.opts.show_custom_attributes {
                for (_, entry) in cil_type.interfaces.iter() {
                    if entry.custom_attributes.is_empty() {
                        continue;
                    }
                    if let Some(iface) = entry.interface.upgrade() {
                        writeln!(
                            w,
                            "  .interfaceimpl type {}",
                            assembly_scoped_name(&iface, asm)
                        )?;
                        attributes::format_custom_attributes(
                            w,
                            &entry.custom_attributes,
                            "  ",
                            asm,
                        )?;
                    }
                }
            }

            // .param type directives for generic parameters with custom attributes
            if self.opts.show_custom_attributes {
                generics::format_generic_param_custom_attributes(
                    w,
                    &cil_type.generic_params,
                    "  ",
                    asm,
                )?;
            }

            if self.opts.show_security {
                for (_, sec) in cil_type.security.iter() {
                    security::format_security(w, sec, "  ")?;
                }
            }

            fields::format_fields(&self.opts, w, cil_type, asm)?;
        }

        for method in &cil_type.query_methods() {
            self.format_method(w, &method, entry_point_token, asm, vtfixup_ctx)?;
        }

        if !self.opts.raw {
            properties::format_properties(&self.opts, w, cil_type, asm)?;
            events::format_events(&self.opts, w, cil_type, asm)?;

            // Emit nested types inside the parent class body
            for (_, nested_ref) in cil_type.nested_types.iter() {
                if let Some(nested_type) = nested_ref.upgrade() {
                    writeln!(w)?;
                    self.format_type(w, &nested_type, asm, entry_point_token, vtfixup_ctx)?;
                }
            }

            types::format_type_end(w, cil_type)?;
        }

        Ok(())
    }

    /// Format a single method: header, body, and closing brace.
    ///
    /// Emits the `.method` header, opening brace, `.entrypoint` (if applicable),
    /// `.vtentry` / `.export` (for VTableFixup methods), custom attributes,
    /// security declarations, `.override` directive (for explicit interface/base
    /// method implementations), `.param` directives (for parameter defaults and
    /// marshalling), the IL method body (`.maxstack`, `.locals`, instructions),
    /// and the closing brace with end-of-method comment.
    pub fn format_method(
        &self,
        w: &mut dyn Write,
        method: &Method,
        entry_point_token: u32,
        asm: &CilObject,
        vtfixup_ctx: Option<&VtFixupContext>,
    ) -> io::Result<()> {
        if self.opts.raw {
            return method_body::format_method_body_raw(&self.opts, w, method, asm);
        }

        methods::format_method_header(w, method, asm)?;
        writeln!(w, "  {{")?;

        if method.token.value() == entry_point_token {
            writeln!(w, "    .entrypoint")?;
        }

        if let Some(ctx) = vtfixup_ctx {
            vtfixup::format_method_vtentry_export(w, method.token.value(), ctx)?;
        }

        if self.opts.show_custom_attributes {
            attributes::format_custom_attributes(w, &method.custom_attributes, "    ", asm)?;
        }
        if self.opts.show_security {
            for (_, sec) in method.security.iter() {
                security::format_security(w, sec, "    ")?;
            }
        }

        // .param type directives for method-level generic parameters with custom attributes
        if self.opts.show_custom_attributes {
            generics::format_generic_param_custom_attributes(
                w,
                &method.generic_params,
                "    ",
                asm,
            )?;
        }

        // .override directives for explicit interface/base method implementations
        for (_, override_decl) in method.overrides.iter() {
            format_override_directive(w, override_decl, asm)?;
        }

        // .param directives for parameter defaults, marshalling, and custom attributes
        for (_, param) in method.params.iter() {
            if param.sequence == 0 {
                // Return value parameter — emit custom attributes if present
                if self.opts.show_custom_attributes && !param.custom_attributes.is_empty() {
                    writeln!(w, "    .param [0]")?;
                    attributes::format_custom_attributes(w, &param.custom_attributes, "    ", asm)?;
                }
                continue;
            }
            let has_default = param.flags.contains(ParamAttributes::HAS_DEFAULT);
            let has_marshal = param.flags.contains(ParamAttributes::HAS_FIELD_MARSHAL);
            let has_custom_attrs =
                self.opts.show_custom_attributes && !param.custom_attributes.is_empty();

            if has_default {
                if let Some(default) = param.default.get() {
                    writeln!(
                        w,
                        "    .param [{}] = {}",
                        param.sequence,
                        format_constant(default)
                    )?;
                    // Custom attributes follow the .param directive
                    if has_custom_attrs {
                        attributes::format_custom_attributes(
                            w,
                            &param.custom_attributes,
                            "    ",
                            asm,
                        )?;
                    }
                }
            } else if has_marshal {
                if let Some(marshal) = param.marshal.get() {
                    writeln!(w, "    .param [{}] marshal({marshal})", param.sequence)?;
                }
                if has_custom_attrs {
                    attributes::format_custom_attributes(w, &param.custom_attributes, "    ", asm)?;
                }
            } else if has_custom_attrs {
                // No default or marshal, but has custom attributes
                writeln!(w, "    .param [{}]", param.sequence)?;
                attributes::format_custom_attributes(w, &param.custom_attributes, "    ", asm)?;
            }
        }

        // Abstract, native, and runtime methods have no IL body
        let has_body = !method.is_abstract()
            && !method.is_code_native()
            && !method.is_code_runtime()
            && method.body.get().is_some();

        if has_body {
            method_body::format_method_body(&self.opts, w, method, asm)?;
        }

        writeln!(w, "{}", methods::method_end_comment(method))?;
        writeln!(w)?;
        Ok(())
    }
}

/// Format a single `.override` directive for explicit interface/base method implementations.
///
/// Produces either:
/// - Simple form: `.override TypeName::MethodName` (when declaration parent is NOT a TypeSpec)
/// - Full method-ref form: `.override method instance void class IFoo`1<int32>::Bar(params)`
///   (when declaration parent IS a TypeSpec, e.g. generic type instantiation)
fn format_override_directive(
    w: &mut dyn Write,
    decl: &CilTypeReference,
    asm: &CilObject,
) -> io::Result<()> {
    match decl {
        CilTypeReference::MethodDef(method_ref) => {
            // Same-assembly override: simple form
            if let Some(method) = method_ref.upgrade() {
                if let Some(parent_type) = method.declaring_type_fullname() {
                    writeln!(
                        w,
                        "    .override {}::{}",
                        quote_identifier(&parent_type),
                        quote_identifier(&method.name)
                    )?;
                }
            }
        }
        CilTypeReference::MemberRef(mref) => {
            // Cross-assembly override: check if parent is TypeSpec for full form
            let needs_method_form = matches!(mref.declaredby, CilTypeReference::TypeSpec(_));

            if needs_method_form {
                // Full form: .override method instance void class IFoo`1<int32>::Bar(params)
                let method_sig =
                    resolve_token(asm, mref.token).unwrap_or_else(|| format!("[?]::{}", mref.name));
                writeln!(w, "    .override method {method_sig}")?;
            } else {
                // Simple form: .override TypeName::MethodName
                let declaring = resolve_declaring_type(&mref.declaredby, asm);
                writeln!(
                    w,
                    "    .override {}::{}",
                    declaring,
                    quote_identifier(&mref.name)
                )?;
            }
        }
        _ => {} // Other CilTypeReference variants shouldn't appear in override context
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    use crate::{
        formatting::{FormatterOptions, IlFormatter},
        metadata::token::Token,
        testkit::fixture,
        CilObject,
    };

    fn load_crafted_2() -> CilObject {
        let path = fixture("crafted_2.exe");
        CilObject::from_path(&path).expect("Failed to load crafted_2.exe")
    }

    fn format_type_by_name(asm: &CilObject, type_name: &str) -> String {
        let formatter = IlFormatter::new(FormatterOptions::default());
        let cil_type = asm
            .query_types()
            .defined()
            .filter(|t| &*t.fullname() == type_name)
            .find_all()
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("Type '{type_name}' not found"));
        let mut buf = Vec::new();
        formatter
            .format_type(&mut buf, &cil_type, asm, 0, None)
            .expect("format_type failed");
        String::from_utf8(buf).unwrap()
    }

    fn format_method_by_token(asm: &CilObject, token: u32) -> String {
        let formatter = IlFormatter::new(FormatterOptions::default());
        let method = asm
            .methods()
            .get(&Token::new(token))
            .expect("Method not found");
        let mut buf = Vec::new();
        formatter
            .format_method(&mut buf, method.value(), 0, asm, None)
            .expect("format_method failed");
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn test_generic_type_params() {
        let asm = load_crafted_2();
        // GenericStruct`2 has generic params T (struct constraint) and U
        let output = format_type_by_name(&asm, "GenericStruct`2");
        // Generic params appear as <... !0, ... !1> with optional constraints
        assert!(output.contains("!0"), "Missing generic param !0: {output}");
        assert!(output.contains("!1"), "Missing generic param !1: {output}");
        assert!(
            output.contains(".class"),
            "Missing .class directive: {output}"
        );
    }

    /// A constraint that is a type specification is written from its signature, with its
    /// arguments: `IEquatable<TKey>` was written `IEquatable`1`, another type.
    #[test]
    fn a_type_specification_constraint_keeps_its_arguments() {
        let asm = load_crafted_2();
        let output = format_type_by_name(&asm, "ComplexGeneric`3");
        let header = output
            .lines()
            .find(|line| line.starts_with(".class"))
            .unwrap();
        assert!(
            header.contains("(class [mscorlib]'System.IEquatable`1'<!0>) TKey"),
            "{header}"
        );
    }

    #[test]
    fn test_type_pack_size() {
        let asm = load_crafted_2();
        // StructWithExplicitLayout has .size 16
        let output = format_type_by_name(&asm, "StructWithExplicitLayout");
        assert!(
            output.contains(".size 16"),
            "Missing .size directive: {output}"
        );
    }

    #[test]
    fn test_field_defaults() {
        let asm = load_crafted_2();
        // TestEnum has literal fields with default values
        let output = format_type_by_name(&asm, "TestEnum");
        assert!(
            output.contains("literal"),
            "Missing literal modifier: {output}"
        );
        assert!(
            output.contains("Value1 = int64(0x1)"),
            "Missing Value1 default: {output}"
        );
        assert!(
            output.contains("Value3 = int64(0x4)"),
            "Missing Value3 default: {output}"
        );
    }

    #[test]
    fn test_field_marshal() {
        let asm = load_crafted_2();
        // DerivedClass has _marshaledField with marshal(lpwstr)
        let output = format_type_by_name(&asm, "DerivedClass");
        assert!(
            output.contains("marshal("),
            "Missing marshal directive: {output}"
        );
        assert!(
            output.contains("_marshaledField"),
            "Missing marshaled field: {output}"
        );
    }

    #[test]
    fn test_property_accessors() {
        let asm = load_crafted_2();
        // Person has FirstName, LastName, Age properties
        let output = format_type_by_name(&asm, "Person");
        assert!(output.contains(".property"), "Missing .property: {output}");
        assert!(
            output.contains(".get instance"),
            "Missing .get accessor: {output}"
        );
        assert!(
            output.contains(".set instance"),
            "Missing .set accessor: {output}"
        );
        assert!(
            output.contains("::get_FirstName()"),
            "Missing getter method ref: {output}"
        );
    }

    #[test]
    fn test_event_accessors() {
        let asm = load_crafted_2();
        // DerivedClass has Event1 and CustomEvent
        let output = format_type_by_name(&asm, "DerivedClass");
        assert!(output.contains(".event"), "Missing .event: {output}");
        assert!(output.contains(".addon"), "Missing .addon: {output}");
        assert!(output.contains(".removeon"), "Missing .removeon: {output}");
    }

    #[test]
    fn test_custom_attribute_format() {
        let asm = load_crafted_2();
        // TestEnum has FlagsAttribute custom attribute
        let output = format_type_by_name(&asm, "TestEnum");
        assert!(
            output.contains(".custom instance void"),
            "Missing constructor ref in .custom: {output}"
        );
        assert!(output.contains("= ("), "Missing raw blob bytes: {output}");
    }

    #[test]
    fn test_custom_attribute_comment_before_directive() {
        let asm = load_crafted_2();
        // DerivedClass has MetadataTestAttribute with fixed args
        let output = format_type_by_name(&asm, "DerivedClass");
        // Find the comment and .custom lines
        if let Some((_, after_comment)) = output.split_once("// (int32(100)") {
            // Searching the text that *follows* the comment states the property directly. The
            // previous form sliced from the comment's own offset and asserted the directive's
            // index was non-zero, which no match could ever violate.
            assert!(
                after_comment.contains(".custom "),
                "Comment should appear before .custom directive"
            );
        }
    }

    #[test]
    fn test_type_signature_resolution() {
        let asm = load_crafted_2();
        // DerivedClass methods should have resolved type names
        let output = format_type_by_name(&asm, "DerivedClass");
        // Should NOT contain unresolved class[XXXXXXXX] tokens
        assert!(
            !output.contains("class[0"),
            "Found unresolved class token: {output}"
        );
        assert!(
            !output.contains("valuetype[0"),
            "Found unresolved valuetype token: {output}"
        );
    }

    #[test]
    fn test_pe_header_directives() {
        let asm = load_crafted_2();
        let formatter = IlFormatter::new(FormatterOptions::default());
        let mut buf = Vec::new();
        formatter
            .format_assembly(&mut buf, &asm)
            .expect("format_assembly failed");
        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains(".imagebase"),
            "Missing .imagebase: {output}"
        );
        assert!(
            output.contains(".subsystem"),
            "Missing .subsystem: {output}"
        );
        assert!(
            output.contains(".file alignment"),
            "Missing .file alignment: {output}"
        );
        assert!(
            output.contains(".stackreserve"),
            "Missing .stackreserve: {output}"
        );
        assert!(output.contains(".corflags"), "Missing .corflags: {output}");
    }

    #[test]
    fn test_method_body_locals() {
        let asm = load_crafted_2();
        // DerivedClass::MethodWithLocals (0x0600002C) has 4 locals
        let output = format_method_by_token(&asm, 0x0600002C);
        assert!(
            output.contains(".locals init ("),
            "Missing .locals init: {output}"
        );
        assert!(output.contains("V_0"), "Missing local V_0: {output}");
    }

    #[test]
    fn test_exception_handlers() {
        let asm = load_crafted_2();
        // DerivedClass::MethodWithLocals (0x0600002C) has try/catch/finally
        let output = format_method_by_token(&asm, 0x0600002C);
        assert!(output.contains(".try"), "Missing .try block: {output}");
        assert!(output.contains("catch"), "Missing catch block: {output}");
        assert!(
            output.contains("finally"),
            "Missing finally block: {output}"
        );
    }

    #[test]
    fn test_assembly_extern_refs() {
        let asm = load_crafted_2();
        let formatter = IlFormatter::new(FormatterOptions::default());
        let mut buf = Vec::new();
        formatter
            .format_assembly(&mut buf, &asm)
            .expect("format_assembly failed");
        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains(".assembly extern 'mscorlib'"),
            "Missing mscorlib extern ref: {output}"
        );
        assert!(
            output.contains(".ver 4:0:0:0"),
            "Missing version in extern ref: {output}"
        );
    }

    #[test]
    fn test_raw_mode() {
        let asm = load_crafted_2();
        let opts = FormatterOptions {
            raw: true,
            ..Default::default()
        };
        let formatter = IlFormatter::new(opts);
        // Format a method with a body: DerivedClass::MethodWithLocals
        let method = asm
            .methods()
            .get(&Token::new(0x0600002C))
            .expect("Method not found");
        let mut buf = Vec::new();
        formatter
            .format_method(&mut buf, method.value(), 0, &asm, None)
            .expect("format_method failed");
        let output = String::from_utf8(buf).unwrap();
        // Raw mode should have IL instructions but no .method header
        assert!(
            !output.contains(".method"),
            "Raw mode should not have .method: {output}"
        );
        assert!(
            !output.contains(".locals"),
            "Raw mode should not have .locals: {output}"
        );
        // Should have IL offset labels
        assert!(
            output.contains("IL_"),
            "Missing IL labels in raw mode: {output}"
        );
    }

    #[test]
    fn test_method_header_modifiers() {
        let asm = load_crafted_2();
        // IBaseInterface::Method1 (0x0600000A) is abstract virtual
        let output = format_method_by_token(&asm, 0x0600000A);
        assert!(
            output.contains("abstract"),
            "Missing abstract modifier: {output}"
        );
        assert!(
            output.contains("virtual"),
            "Missing virtual modifier: {output}"
        );
    }

    #[test]
    fn test_static_method() {
        let asm = load_crafted_2();
        // Program::Main (0x06000039)
        let output = format_method_by_token(&asm, 0x06000039);
        assert!(
            output.contains("static"),
            "Missing static modifier: {output}"
        );
        assert!(
            output.contains(".method"),
            "Missing .method directive: {output}"
        );
    }

    #[test]
    fn test_implements_clause() {
        let asm = load_crafted_2();
        // DerivedClass implements IBaseInterface and IDerivedInterface
        let output = format_type_by_name(&asm, "DerivedClass");
        assert!(
            output.contains("implements"),
            "Missing implements clause: {output}"
        );
        assert!(
            output.contains("IBaseInterface"),
            "Missing IBaseInterface in implements: {output}"
        );
    }

    #[test]
    fn test_interfaceimpl_directive_order() {
        // Verify ILDasm-compliant ordering: type CAs, then .interfaceimpl, then .param type, then .permissionset
        let asm = load_crafted_2();
        let formatter = IlFormatter::new(FormatterOptions::default());
        let mut buf = Vec::new();
        formatter
            .format_assembly(&mut buf, &asm)
            .expect("format_assembly failed");
        let output = String::from_utf8(buf).unwrap();

        // If any .interfaceimpl directives are present, they should come before .param type
        if let Some(iimpl_pos) = output.find(".interfaceimpl type") {
            if let Some(param_pos) = output.find(".param type") {
                assert!(
                    iimpl_pos < param_pos,
                    ".interfaceimpl should come before .param type (ILDasm order)"
                );
            }
        }
    }

    fn load_dotnet_10(name: &str) -> CilObject {
        let path = fixture("dotnet_10.0").join(name);
        CilObject::from_path(&path).unwrap_or_else(|e| panic!("Failed to load {name}: {e}"))
    }

    #[test]
    fn test_interfaceimpl_custom_attributes_dotnet10() {
        // .NET 10 BCL assemblies have NullableAttribute on InterfaceImpl entries
        let asm = load_dotnet_10("System.Collections.dll");

        // Find types that have InterfaceImpl entries with custom attributes
        let mut types_with_iimpl_cas = Vec::new();
        for t in asm.query_types().defined().find_all() {
            for (_, entry) in t.interfaces.iter() {
                if !entry.custom_attributes.is_empty() {
                    if let Some(iface) = entry.interface.upgrade() {
                        types_with_iimpl_cas.push((t.fullname(), iface.fullname()));
                    }
                }
            }
        }

        assert!(
            !types_with_iimpl_cas.is_empty(),
            "Expected .NET 10 System.Collections.dll to have InterfaceImpl custom attributes"
        );

        // Format a type that has InterfaceImpl CAs and verify output
        let (type_name, _) = &types_with_iimpl_cas[0];
        let formatter = IlFormatter::new(FormatterOptions::default());
        let cil_type = asm
            .query_types()
            .defined()
            .filter(|t| t.fullname() == *type_name)
            .find_all()
            .into_iter()
            .next()
            .unwrap();
        let mut buf = Vec::new();
        formatter
            .format_type(&mut buf, &cil_type, &asm, 0, None)
            .expect("format_type failed");
        let output = String::from_utf8(buf).unwrap();

        assert!(
            output.contains(".interfaceimpl type"),
            "Missing .interfaceimpl directive for {type_name}: {output}"
        );
        assert!(
            output.contains(".custom"),
            "Missing .custom under .interfaceimpl for {type_name}: {output}"
        );
    }
}

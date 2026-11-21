//! Generic parameter and constraint formatting.
//!
//! Formats generic parameter lists using ILAsm positional notation (`<!0, !!0>`)
//! with proper constraint syntax: flag constraints as space-separated keywords
//! outside parentheses, type constraints inside parentheses with assembly-scoped names.

use std::io::{self, Write};

use crate::{
    formatting::{
        attributes,
        helpers::{assembly_scoped_name, quote_identifier},
    },
    metadata::{
        tables::{GenericParamAttributes, GenericParamList},
        typesystem::CilFlavor,
    },
    CilObject,
};

/// Format a [`GenericParamList`] as ILAsm generic parameter syntax.
///
/// Produces a string like `<!0, !1>` for type-level generic parameters or
/// `<!!0, !!1>` for method-level parameters, with proper ILAsm constraint syntax:
/// `<valuetype .ctor([mscorlib]System.ValueType) !!0>`.
///
/// Flag constraints (`class`, `valuetype`, `.ctor`) are space-separated keywords.
/// Type/interface constraints are parenthesized with assembly-scoped names.
fn format_generic_params(params: &GenericParamList, asm: &CilObject) -> String {
    if params.is_empty() {
        return String::new();
    }

    let mut result = String::from("<");
    for (i, param) in params.iter() {
        if i > 0 {
            result.push_str(", ");
        }

        // Variance prefix
        let vk = param.flags.variance_keyword();
        if !vk.is_empty() {
            result.push_str(vk);
        }

        // Flag constraints (space-separated keywords)
        let has_class = param
            .flags
            .contains(GenericParamAttributes::REFERENCE_TYPE_CONSTRAINT);
        let has_valuetype = param
            .flags
            .contains(GenericParamAttributes::NOT_NULLABLE_VALUE_TYPE_CONSTRAINT);
        if has_class {
            result.push_str("class ");
        }
        if has_valuetype {
            result.push_str("valuetype ");
        }
        if param
            .flags
            .contains(GenericParamAttributes::DEFAULT_CONSTRUCTOR_CONSTRAINT)
        {
            result.push_str(".ctor ");
        }
        if param
            .flags
            .contains(GenericParamAttributes::ALLOW_BY_REF_LIKE)
        {
            result.push_str("allow(byreflike) ");
        }

        // Type/interface constraints — all inside a single set of parentheses,
        // comma-separated per the ILAsm grammar: (IFoo, IBar, IBaz)
        // Filter out types implied by flag constraints (System.ValueType for valuetype,
        // System.Object for class).
        let mut type_constraints = Vec::new();
        for (_, constraint_ref) in param.constraints.iter() {
            if let Some(constraint_type) = constraint_ref.upgrade() {
                // Skip System.ValueType when valuetype flag is set (redundant)
                if has_valuetype
                    && constraint_type.name == "ValueType"
                    && constraint_type.namespace == "System"
                {
                    continue;
                }
                // Skip System.Object when class flag is set (redundant)
                if has_class
                    && constraint_type.name == "Object"
                    && constraint_type.namespace == "System"
                {
                    continue;
                }
                // Generic parameter constraints use positional notation: !N for type params, !!N for method params
                let name = if let CilFlavor::GenericParameter { index, method } =
                    constraint_type.flavor()
                {
                    if *method {
                        format!("!!{index}")
                    } else {
                        format!("!{index}")
                    }
                } else {
                    assembly_scoped_name(&constraint_type, asm)
                };
                type_constraints.push(name);
            }
        }
        if !type_constraints.is_empty() {
            result.push('(');
            result.push_str(&type_constraints.join(", "));
            result.push_str(") ");
        }

        // Generic param name (declarations use names, not positional notation)
        result.push_str(&quote_identifier(&param.name));
    }
    result.push('>');
    result
}

/// Write generic parameters to a writer stream.
///
/// Calls [`format_generic_params`] and writes the result to `w`. Does
/// nothing if the parameter list is empty.
pub fn write_generic_params(
    w: &mut dyn Write,
    params: &GenericParamList,
    asm: &CilObject,
) -> io::Result<()> {
    let formatted = format_generic_params(params, asm);
    if !formatted.is_empty() {
        write!(w, "{formatted}")?;
    }
    Ok(())
}

/// Emit `.param type` directives for generic parameters that have custom attributes.
///
/// ILAsm syntax: `.param type T` followed by `.custom` directives.
/// Only emits directives for generic parameters that actually have custom attributes.
pub fn format_generic_param_custom_attributes(
    w: &mut dyn Write,
    params: &GenericParamList,
    indent: &str,
    asm: &CilObject,
) -> io::Result<()> {
    for (_, param) in params.iter() {
        if param.custom_attributes.is_empty() {
            continue;
        }
        writeln!(w, "{indent}.param type {}", quote_identifier(&param.name))?;
        attributes::format_custom_attributes(w, &param.custom_attributes, indent, asm)?;
    }
    Ok(())
}

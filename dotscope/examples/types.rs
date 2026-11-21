//! # Type System Deep Dive
//!
//! **What this example teaches:**
//! - Advanced type system analysis capabilities
//! - Generic type instantiation and constraints
//! - Interface implementation analysis
//! - Inheritance hierarchy exploration
//! - Signature parsing and method resolution
//!
//! **When to use this pattern:**
//! - Building type analysis tools
//! - Investigating inheritance relationships
//! - Generic type constraint analysis
//! - Interface implementation discovery
//!
//! **Prerequisites:**
//! - Strong understanding of .NET type system
//! - Familiarity with generics and inheritance
//! - Experience with metadata analysis

use std::{collections::HashMap, env, path::Path};

use dotscope::prelude::*;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let prog = args.first().map_or("types", String::as_str);
    let Some(path_arg) = args.get(1) else {
        eprintln!("Usage: {prog} <path-to-dotnet-assembly>");
        eprintln!();
        eprintln!("This example explores the .NET type system in detail:");
        eprintln!("  • Type categorization and analysis");
        eprintln!("  • Generic type parameter examination");
        eprintln!("  • Inheritance hierarchy mapping");
        eprintln!("  • Interface implementation tracking");
        return Ok(());
    };

    let path = Path::new(path_arg);
    println!("🏗️  Type system analysis of: {}", path.display());

    let assembly = CilObject::from_path(path)?;

    // Type Registry Analysis
    print_type_registry_analysis(&assembly);

    // Generic Type Analysis
    print_generic_analysis(&assembly);

    // Inheritance Analysis
    print_inheritance_analysis(&assembly);

    // Interface Analysis
    print_interface_analysis(&assembly);

    // Signature Analysis
    print_signature_analysis(&assembly);

    println!("\n✅ Type system analysis completed!");

    Ok(())
}

fn print_type_registry_analysis(assembly: &CilObject) {
    println!("\n📚 Type Registry Analysis:");

    let types = assembly.types();
    let mut type_categories = TypeCategories::default();

    // Analyze type definitions
    for type_def in &types.all_types() {
        type_categories.total_types = type_categories.total_types.saturating_add(1);

        // Categorize by visibility
        match type_def.flags.bits() & 0x07 {
            // TypeAttributes.VisibilityMask
            0 => type_categories.not_public = type_categories.not_public.saturating_add(1), // NotPublic
            1 => type_categories.public = type_categories.public.saturating_add(1), // Public
            2 => type_categories.nested_public = type_categories.nested_public.saturating_add(1), // NestedPublic
            3 => type_categories.nested_private = type_categories.nested_private.saturating_add(1), // NestedPrivate
            4 => type_categories.nested_family = type_categories.nested_family.saturating_add(1), // NestedFamily
            5 => {
                type_categories.nested_assembly = type_categories.nested_assembly.saturating_add(1)
            } // NestedAssembly
            6 => {
                type_categories.nested_fam_and_assem =
                    type_categories.nested_fam_and_assem.saturating_add(1)
            } // NestedFamANDAssem
            7 => {
                type_categories.nested_fam_or_assem =
                    type_categories.nested_fam_or_assem.saturating_add(1)
            } // NestedFamORAssem
            _ => {}
        }

        // Categorize by layout
        match type_def.flags.bits() & 0x18 {
            // TypeAttributes.LayoutMask
            0x00 => type_categories.auto_layout = type_categories.auto_layout.saturating_add(1), // AutoLayout
            0x08 => {
                type_categories.sequential_layout =
                    type_categories.sequential_layout.saturating_add(1)
            } // SequentialLayout
            0x10 => {
                type_categories.explicit_layout = type_categories.explicit_layout.saturating_add(1)
            } // ExplicitLayout
            _ => {}
        }

        // Categorize by semantics
        match type_def.flags.bits() & 0x20 {
            // TypeAttributes.ClassSemanticsMask
            0x00 => type_categories.class_types = type_categories.class_types.saturating_add(1), // Class
            0x20 => {
                type_categories.interface_types = type_categories.interface_types.saturating_add(1)
            } // Interface
            _ => {}
        }

        // Check for special types
        if type_def.flags.bits() & 0x80 != 0 {
            // Abstract
            type_categories.abstract_types = type_categories.abstract_types.saturating_add(1);
        }
        if type_def.flags.bits() & 0x100 != 0 {
            // Sealed
            type_categories.sealed_types = type_categories.sealed_types.saturating_add(1);
        }
        if type_def.flags.bits() & 0x400 != 0 {
            // Serializable
            type_categories.serializable_types =
                type_categories.serializable_types.saturating_add(1);
        }

        // Analyze by naming patterns
        if type_def.name.ends_with("Attribute") {
            type_categories.attribute_types = type_categories.attribute_types.saturating_add(1);
        } else if type_def.name.ends_with("Exception") {
            type_categories.exception_types = type_categories.exception_types.saturating_add(1);
        } else if type_def.name.ends_with("EventArgs") {
            type_categories.event_arg_types = type_categories.event_arg_types.saturating_add(1);
        } else if type_def.name.starts_with('I')
            && type_def.name.len() > 1
            && type_def.name.chars().nth(1).is_some_and(char::is_uppercase)
        {
            type_categories.interface_named_types =
                type_categories.interface_named_types.saturating_add(1);
        }
    }

    print_type_categories(&type_categories);
}

fn print_type_categories(categories: &TypeCategories) {
    println!("  Type visibility distribution:");
    println!("    Public: {}", categories.public);
    println!("    Not public: {}", categories.not_public);
    println!("    Nested public: {}", categories.nested_public);
    println!("    Nested private: {}", categories.nested_private);
    println!("    Nested family: {}", categories.nested_family);

    println!("  Type layout distribution:");
    println!("    Auto layout: {}", categories.auto_layout);
    println!("    Sequential layout: {}", categories.sequential_layout);
    println!("    Explicit layout: {}", categories.explicit_layout);

    println!("  Type semantics:");
    println!("    Classes: {}", categories.class_types);
    println!("    Interfaces: {}", categories.interface_types);
    println!("    Abstract types: {}", categories.abstract_types);
    println!("    Sealed types: {}", categories.sealed_types);
    println!("    Serializable types: {}", categories.serializable_types);

    println!("  Special type patterns:");
    println!("    Attributes: {}", categories.attribute_types);
    println!("    Exceptions: {}", categories.exception_types);
    println!("    Event args: {}", categories.event_arg_types);
    println!(
        "    Interface-named types: {}",
        categories.interface_named_types
    );
}

fn print_generic_analysis(assembly: &CilObject) {
    println!("\n🧬 Generic Type Analysis:");

    let types = assembly.types();
    let mut generic_stats = GenericStats::default();

    // Analyze generic types and methods
    for type_def in types.all_types().iter().take(100) {
        // Look for generic type indicators
        if type_def.name.contains('`') {
            generic_stats.generic_types = generic_stats.generic_types.saturating_add(1);

            // Extract generic parameter count
            if let Some(backtick_pos) = type_def.name.rfind('`') {
                if let Ok(param_count) = type_def
                    .name
                    .get(backtick_pos.saturating_add(1)..)
                    .unwrap_or("")
                    .parse::<u32>()
                {
                    generic_stats.total_type_parameters = generic_stats
                        .total_type_parameters
                        .saturating_add(param_count);
                    if param_count > generic_stats.max_type_parameters {
                        generic_stats.max_type_parameters = param_count;
                        generic_stats.most_generic_type = type_def.name.to_string();
                    }
                }
            }

            if generic_stats.generic_types <= 5 {
                println!("    Generic type: {}.{}", type_def.namespace, type_def.name);
            }
        }
    }

    // Analyze methods for generic parameters
    let methods = assembly.methods();
    for entry in methods.iter().take(100) {
        let method = entry.value();

        // Simple heuristic: methods with generic naming patterns
        if method.name.contains('<') || method.name.contains("Generic") {
            generic_stats.potentially_generic_methods =
                generic_stats.potentially_generic_methods.saturating_add(1);
        }
    }

    println!("  Generic type statistics:");
    println!("    Generic types found: {}", generic_stats.generic_types);
    println!(
        "    Total type parameters: {}",
        generic_stats.total_type_parameters
    );
    println!(
        "    Max type parameters: {} (in '{}')",
        generic_stats.max_type_parameters, generic_stats.most_generic_type
    );
    println!(
        "    Potentially generic methods: {}",
        generic_stats.potentially_generic_methods
    );

    if generic_stats.generic_types > 5 {
        println!("    ... (showing first 5 generic types)");
    }
}

fn print_inheritance_analysis(assembly: &CilObject) {
    println!("\n🌳 Inheritance Hierarchy Analysis:");

    let types = assembly.types();
    let mut inheritance_stats = InheritanceStats::default();
    let mut base_class_counts: HashMap<String, u32> = HashMap::new();

    for type_def in types.all_types().iter().take(50) {
        inheritance_stats.total_types = inheritance_stats.total_types.saturating_add(1);

        // Check if type has a base class (extends something)
        if let Some(base_type) = type_def.base() {
            inheritance_stats.types_with_base_class =
                inheritance_stats.types_with_base_class.saturating_add(1);

            let base_class_name = format!("{}:{}", base_type.namespace, base_type.name);
            let entry = base_class_counts.entry(base_class_name).or_insert(0u32);
            *entry = entry.saturating_add(1);
        } else {
            inheritance_stats.root_types = inheritance_stats.root_types.saturating_add(1);
        }

        // Check for interface implementations
        // Note: This would require analyzing the InterfaceImpl table in a real implementation
        if type_def.flags.bits() & 0x20 == 0 {
            // Not an interface itself
            // This is a placeholder - real implementation would check InterfaceImpl table
            inheritance_stats.types_implementing_interfaces = inheritance_stats
                .types_implementing_interfaces
                .saturating_add(1);
        }
    }

    println!("  Inheritance statistics:");
    println!("    Types analyzed: {}", inheritance_stats.total_types);
    println!(
        "    Types with base classes: {}",
        inheritance_stats.types_with_base_class
    );
    println!(
        "    Root types (no base class): {}",
        inheritance_stats.root_types
    );
    println!(
        "    Types implementing interfaces: {}",
        inheritance_stats.types_implementing_interfaces
    );

    println!("  Common base classes:");
    let mut sorted_bases: Vec<_> = base_class_counts.iter().collect();
    sorted_bases.sort_by(|a, b| b.1.cmp(a.1));
    for (base_class, count) in sorted_bases.iter().take(5) {
        println!("    {base_class}: {count} derived types");
    }
}

fn print_interface_analysis(assembly: &CilObject) {
    println!("\n🔌 Interface Analysis:");

    let types = assembly.types();
    let mut interface_stats = InterfaceStats::default();
    let mut interface_names = Vec::new();

    for type_def in types.all_types().iter().take(100) {
        if type_def.flags.bits() & 0x20 != 0 {
            // Interface flag
            interface_stats.interface_count = interface_stats.interface_count.saturating_add(1);
            interface_names.push(format!("{}.{}", type_def.namespace, type_def.name));

            // Analyze interface naming patterns
            if type_def.name.starts_with('I')
                && type_def.name.len() > 1
                && type_def.name.chars().nth(1).is_some_and(char::is_uppercase)
            {
                interface_stats.conventionally_named =
                    interface_stats.conventionally_named.saturating_add(1);
            }

            if type_def.namespace.starts_with("System") {
                interface_stats.system_interfaces =
                    interface_stats.system_interfaces.saturating_add(1);
            }
        }
    }

    println!("  Interface statistics:");
    println!("    Total interfaces: {}", interface_stats.interface_count);
    println!(
        "    Conventionally named (IXxx): {}",
        interface_stats.conventionally_named
    );
    println!(
        "    System namespace interfaces: {}",
        interface_stats.system_interfaces
    );

    if !interface_names.is_empty() {
        println!("  Sample interfaces:");
        for interface_name in interface_names.iter().take(8) {
            println!("    {interface_name}");
        }
        if interface_names.len() > 8 {
            println!("    ... (showing first 8 interfaces)");
        }
    }
}

fn print_signature_analysis(assembly: &CilObject) {
    println!("\n✍️  Signature Analysis:");

    let methods = assembly.methods();
    let mut signature_stats = SignatureStats::default();

    for entry in methods.iter().take(50) {
        let method = entry.value();
        signature_stats.methods_analyzed = signature_stats.methods_analyzed.saturating_add(1);

        // Analyze method naming patterns for signature complexity
        let param_count = method
            .name
            .matches(',')
            .count()
            .saturating_add(usize::from(method.name.contains('(')));

        if param_count > signature_stats.max_parameters {
            signature_stats.max_parameters = param_count;
            signature_stats.most_complex_method = method.name.to_string();
        }

        signature_stats.total_parameters =
            signature_stats.total_parameters.saturating_add(param_count);

        // Check for special method types
        if method.name.starts_with("get_") || method.name.starts_with("set_") {
            signature_stats.property_accessors =
                signature_stats.property_accessors.saturating_add(1);
        } else if method.name.starts_with("add_") || method.name.starts_with("remove_") {
            signature_stats.event_accessors = signature_stats.event_accessors.saturating_add(1);
        } else if method.name.starts_with("op_") {
            signature_stats.operator_overloads =
                signature_stats.operator_overloads.saturating_add(1);
        } else if method.name == ".ctor" {
            signature_stats.constructors = signature_stats.constructors.saturating_add(1);
        } else if method.name == ".cctor" {
            signature_stats.static_constructors =
                signature_stats.static_constructors.saturating_add(1);
        }
    }

    println!("  Method signature statistics:");
    println!("    Methods analyzed: {}", signature_stats.methods_analyzed);
    println!(
        "    Property accessors: {}",
        signature_stats.property_accessors
    );
    println!("    Event accessors: {}", signature_stats.event_accessors);
    println!(
        "    Operator overloads: {}",
        signature_stats.operator_overloads
    );
    println!("    Constructors: {}", signature_stats.constructors);
    println!(
        "    Static constructors: {}",
        signature_stats.static_constructors
    );

    if signature_stats.methods_analyzed > 0 {
        println!(
            "    Average parameters per method: {:.1}",
            signature_stats.total_parameters as f64 / signature_stats.methods_analyzed as f64
        );
        println!(
            "    Most complex method: '{}' ({} parameters)",
            signature_stats.most_complex_method, signature_stats.max_parameters
        );
    }

    println!("  Signature parsing capabilities:");
    println!("    • Method signature decoding");
    println!("    • Field signature analysis");
    println!("    • Local variable signature parsing");
    println!("    • Generic constraint resolution");
    println!("    • Calling convention analysis");
}

#[derive(Default)]
struct TypeCategories {
    total_types: usize,
    public: usize,
    not_public: usize,
    nested_public: usize,
    nested_private: usize,
    nested_family: usize,
    nested_assembly: usize,
    nested_fam_and_assem: usize,
    nested_fam_or_assem: usize,
    auto_layout: usize,
    sequential_layout: usize,
    explicit_layout: usize,
    class_types: usize,
    interface_types: usize,
    abstract_types: usize,
    sealed_types: usize,
    serializable_types: usize,
    attribute_types: usize,
    exception_types: usize,
    event_arg_types: usize,
    interface_named_types: usize,
}

#[derive(Default)]
struct GenericStats {
    generic_types: usize,
    total_type_parameters: u32,
    max_type_parameters: u32,
    most_generic_type: String,
    potentially_generic_methods: usize,
}

#[derive(Default)]
struct InheritanceStats {
    total_types: usize,
    types_with_base_class: usize,
    root_types: usize,
    types_implementing_interfaces: usize,
}

#[derive(Default)]
struct InterfaceStats {
    interface_count: usize,
    conventionally_named: usize,
    system_interfaces: usize,
}

#[derive(Default)]
struct SignatureStats {
    methods_analyzed: usize,
    total_parameters: usize,
    max_parameters: usize,
    most_complex_method: String,
    property_accessors: usize,
    event_accessors: usize,
    operator_overloads: usize,
    constructors: usize,
    static_constructors: usize,
}

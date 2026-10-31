//! Call target resolution and Class Hierarchy Analysis (CHA).
//!
//! This module provides resolution of call targets for the call graph, including:
//! - Direct call resolution to method tokens
//! - Virtual call resolution using Class Hierarchy Analysis (CHA)
//! - Type hierarchy tracking for override analysis
//! - External method reference handling
//!
//! Class Hierarchy Analysis is a static analysis technique that determines all
//! possible runtime targets of a virtual method call by analyzing the type
//! hierarchy and finding all methods that override the declared target.

use std::collections::{HashMap, HashSet};

use crate::{
    metadata::{
        method::Method,
        tables::TableId,
        token::Token,
        typesystem::{CilTypeRc, CilTypeReference, TypeRegistry},
    },
    CilObject,
};

/// Resolves call targets using the assembly metadata and type hierarchy.
///
/// The resolver precomputes the type hierarchy and virtual dispatch tables
/// from the assembly metadata, enabling efficient resolution of both direct
/// and virtual method calls during call graph construction.
///
/// For virtual calls, Class Hierarchy Analysis (CHA) is used to determine
/// all possible runtime targets based on the type hierarchy.
#[derive(Debug)]
pub struct CallResolver {
    /// Map from virtual method token to all possible overriders.
    virtual_dispatch_table: HashMap<Token, Vec<Token>>,
    /// Map from method token to its declaring type.
    method_to_type: HashMap<Token, Token>,
    /// Type hierarchy: type token -> direct subtypes (the types deriving from it, or
    /// implementing it when it is an interface), keyed by a generic type's definition.
    type_subtypes: HashMap<Token, Vec<Token>>,
    /// Set of interface types.
    interfaces: HashSet<Token>,
    /// Set of sealed types (cannot be subclassed).
    sealed_types: HashSet<Token>,
}

impl CallResolver {
    /// Creates an empty call resolver with no type hierarchy data.
    ///
    /// This is useful for testing or when no assembly analysis is needed.
    ///
    /// # Returns
    ///
    /// An empty `CallResolver` instance.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            virtual_dispatch_table: HashMap::new(),
            method_to_type: HashMap::new(),
            type_subtypes: HashMap::new(),
            interfaces: HashSet::new(),
            sealed_types: HashSet::new(),
        }
    }

    /// Builds a call resolver from the assembly metadata.
    ///
    /// This constructor precomputes the type hierarchy and virtual dispatch
    /// tables by scanning all types and methods in the assembly. The computed
    /// data structures enable efficient O(1) lookup during call resolution.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to build the resolver from
    ///
    /// # Returns
    ///
    /// A new [`CallResolver`] instance with precomputed dispatch tables.
    #[must_use]
    pub fn new(assembly: &CilObject) -> Self {
        let mut resolver = Self {
            virtual_dispatch_table: HashMap::new(),
            method_to_type: HashMap::new(),
            type_subtypes: HashMap::new(),
            interfaces: HashSet::new(),
            sealed_types: HashSet::new(),
        };

        resolver.build_type_hierarchy(assembly);
        resolver.build_virtual_dispatch_table(assembly);

        resolver
    }

    /// Builds the type hierarchy from assembly metadata.
    fn build_type_hierarchy(&mut self, assembly: &CilObject) {
        let types = assembly.types();

        // First pass: identify interfaces and sealed types
        for type_info in types.all_types() {
            let token = type_info.token;

            // Check if interface
            if type_info.is_interface() {
                self.interfaces.insert(token);
            }

            // Check if sealed
            if type_info.is_sealed() {
                self.sealed_types.insert(token);
            }

            // Map methods to their declaring type
            for method in &type_info.query_methods() {
                self.method_to_type.insert(method.token, token);
            }
        }

        // Second pass: build subtype relationships. A type is a subtype of its base and of
        // every interface it implements, each named by its definition: a type deriving from
        // `Base<int>` overrides the methods `Base<T>` declares.
        let resolver = assembly.resolver();
        let definition = |token: Token| {
            if token.is_table(TableId::TypeSpec) {
                resolver
                    .generic_definition(token)
                    .map_or(token, |definition| definition.token)
            } else {
                token
            }
        };
        for type_info in types.all_types() {
            let supertypes = type_info.base().into_iter().chain(
                type_info
                    .interfaces
                    .iter()
                    .filter_map(|(_, entry)| entry.interface.upgrade()),
            );
            for supertype in supertypes {
                self.type_subtypes
                    .entry(definition(supertype.token))
                    .or_default()
                    .push(type_info.token);
            }
        }
    }

    /// Builds the virtual dispatch table for all virtual methods.
    fn build_virtual_dispatch_table(&mut self, assembly: &CilObject) {
        let methods = assembly.methods();
        let types = assembly.types();

        // Find all virtual methods and their overriders
        for entry in methods {
            let method = entry.value();

            // Skip non-virtual methods
            if !method.is_virtual() {
                continue;
            }

            let method_token = method.token;

            // Get declaring type
            let Some(&declaring_type) = self.method_to_type.get(&method_token) else {
                continue;
            };

            // Find all overriders in derived types
            let mut overriders = vec![method_token]; // Include self
            self.find_overriders(assembly, &types, declaring_type, method, &mut overriders);

            if overriders.len() > 1 {
                self.virtual_dispatch_table.insert(method_token, overriders);
            }
        }
    }

    /// Finds every method of a subtype of `type_token` that may override or implement `base`.
    ///
    /// The set may hold more than the runtime's overrides, never fewer: a pass treats a
    /// virtual call as reaching one body only where nothing else could run, so a method this
    /// misses is a body a pass folds or inlines in place of the one the call reaches. A
    /// candidate is a virtual method that names `base` in a MethodImpl, or one of its name
    /// with as many parameters (its parameter types may be `base`'s with a generic base's
    /// arguments substituted, and a `newslot` one implements an interface method). The walk
    /// visits each subtype once, so an inheritance cycle in malformed metadata ends it.
    fn find_overriders(
        &self,
        assembly: &CilObject,
        types: &TypeRegistry,
        type_token: Token,
        base: &Method,
        overriders: &mut Vec<Token>,
    ) {
        let resolver = assembly.resolver();
        let names_base = |reference: &CilTypeReference| {
            let token = match reference {
                CilTypeReference::MethodDef(method) => method.upgrade().map(|m| m.token),
                CilTypeReference::MemberRef(member) => resolver.resolve_method(member.token),
                _ => None,
            };
            token == Some(base.token)
        };
        let mut visited = HashSet::from([type_token]);
        let mut worklist = vec![type_token];
        while let Some(current) = worklist.pop() {
            for &subtype_token in self.type_subtypes.get(&current).into_iter().flatten() {
                if !visited.insert(subtype_token) {
                    continue;
                }
                worklist.push(subtype_token);
                let Some(subtype) = types.get(&subtype_token) else {
                    continue;
                };
                // A type implements an interface method with a method of its own or one it
                // inherits; it overrides a class's method only with its own
                let inherited: Vec<CilTypeRc> = if self.interfaces.contains(&current) {
                    subtype.base_chain().collect()
                } else {
                    Vec::new()
                };
                let methods = std::iter::once(&subtype)
                    .chain(&inherited)
                    .flat_map(|declaring| declaring.methods.iter());
                for (_, method_ref) in methods {
                    let Some(method) = method_ref.upgrade() else {
                        continue;
                    };
                    let candidate = method.is_virtual()
                        && (method.overrides.iter().any(|(_, r)| names_base(r))
                            || (method.name == base.name
                                && method.signature.params.len() == base.signature.params.len()
                                && method.signature.param_count_generic
                                    == base.signature.param_count_generic));
                    if candidate && !overriders.contains(&method.token) {
                        overriders.push(method.token);
                    }
                }
            }
        }
    }

    /// Resolves possible targets for a virtual call.
    ///
    /// Uses Class Hierarchy Analysis (CHA) to determine all methods that could
    /// be invoked at runtime due to virtual dispatch. This includes the declared
    /// method and all overriding methods in derived types.
    ///
    /// # Arguments
    ///
    /// * `method_token` - The token of the declared virtual method being called
    ///
    /// # Returns
    ///
    /// A vector of method tokens representing all possible runtime targets.
    /// If no overrides exist, returns a single-element vector containing the
    /// original method token.
    #[must_use]
    pub fn resolve_virtual(&self, method_token: Token) -> Vec<Token> {
        self.virtual_dispatch_table
            .get(&method_token)
            .cloned()
            .unwrap_or_else(|| vec![method_token])
    }

    /// Returns `true` if the method is virtual and has multiple possible targets.
    ///
    /// A polymorphic method is one where Class Hierarchy Analysis determined
    /// that more than one implementation could be invoked at runtime.
    ///
    /// # Arguments
    ///
    /// * `method_token` - The method token to check
    ///
    /// # Returns
    ///
    /// `true` if the method has more than one possible runtime target,
    /// `false` otherwise.
    #[must_use]
    pub fn is_polymorphic(&self, method_token: Token) -> bool {
        self.virtual_dispatch_table
            .get(&method_token)
            .is_some_and(|targets| targets.len() > 1)
    }

    /// Returns the declaring type of a method.
    ///
    /// # Arguments
    ///
    /// * `method_token` - The method token to look up
    ///
    /// # Returns
    ///
    /// The type token of the declaring type, or `None` if the method is not
    /// found in the resolver's index.
    #[must_use]
    pub fn declaring_type(&self, method_token: Token) -> Option<Token> {
        self.method_to_type.get(&method_token).copied()
    }

    /// Returns `true` if the type is an interface.
    ///
    /// # Arguments
    ///
    /// * `type_token` - The type token to check
    ///
    /// # Returns
    ///
    /// `true` if the type has the interface attribute, `false` otherwise.
    #[must_use]
    pub fn is_interface(&self, type_token: Token) -> bool {
        self.interfaces.contains(&type_token)
    }

    /// Returns `true` if the type is sealed (cannot be subclassed).
    ///
    /// # Arguments
    ///
    /// * `type_token` - The type token to check
    ///
    /// # Returns
    ///
    /// `true` if the type has the sealed attribute, `false` otherwise.
    #[must_use]
    pub fn is_sealed(&self, type_token: Token) -> bool {
        self.sealed_types.contains(&type_token)
    }

    /// Returns all direct subtypes of a given type.
    ///
    /// Only returns the types that directly derive from the specified type, or
    /// implement it when it is an interface, not transitive descendants. A
    /// generic type's subtypes are those of any of its instantiations.
    ///
    /// # Arguments
    ///
    /// * `type_token` - The type token to find subtypes for
    ///
    /// # Returns
    ///
    /// A vector of type tokens for all direct subtypes. Returns an empty
    /// vector if the type has no subtypes or is not found.
    #[must_use]
    pub fn subtypes(&self, type_token: Token) -> Vec<Token> {
        self.type_subtypes
            .get(&type_token)
            .cloned()
            .unwrap_or_default()
    }

    /// Returns all types in the subtype hierarchy (transitive closure).
    ///
    /// Computes all types that derive from the specified type or implement it,
    /// including indirect descendants through the entire inheritance chain.
    ///
    /// # Arguments
    ///
    /// * `type_token` - The type token to find all subtypes for
    ///
    /// # Returns
    ///
    /// A vector of type tokens for all transitive subtypes. Returns an empty
    /// vector if the type has no subtypes.
    #[must_use]
    pub fn all_subtypes(&self, type_token: Token) -> Vec<Token> {
        let mut result = Vec::new();
        let mut worklist = vec![type_token];
        let mut visited = HashSet::new();

        while let Some(current) = worklist.pop() {
            if !visited.insert(current) {
                continue;
            }

            if let Some(subtypes) = self.type_subtypes.get(&current) {
                for &subtype in subtypes {
                    result.push(subtype);
                    worklist.push(subtype);
                }
            }
        }

        result
    }

    /// Returns statistics about the resolver state.
    ///
    /// Provides aggregate information about the precomputed type hierarchy
    /// and virtual dispatch tables.
    ///
    /// # Returns
    ///
    /// A [`ResolverStats`] structure containing counts and metrics about
    /// the resolver's state.
    #[must_use]
    pub fn stats(&self) -> ResolverStats {
        let polymorphic_methods = self
            .virtual_dispatch_table
            .values()
            .filter(|targets| targets.len() > 1)
            .count();

        let max_targets = self
            .virtual_dispatch_table
            .values()
            .map(Vec::len)
            .max()
            .unwrap_or(0);

        ResolverStats {
            total_methods: self.method_to_type.len(),
            virtual_methods: self.virtual_dispatch_table.len(),
            polymorphic_methods,
            max_targets,
            total_types: self
                .type_subtypes
                .len()
                .saturating_add(self.sealed_types.len()),
            interface_types: self.interfaces.len(),
            sealed_types: self.sealed_types.len(),
        }
    }
}

/// Statistics about the call resolver state.
#[derive(Debug, Clone, Default)]
pub struct ResolverStats {
    /// Total number of methods indexed.
    pub total_methods: usize,
    /// Number of virtual methods.
    pub virtual_methods: usize,
    /// Number of methods with multiple possible targets.
    pub polymorphic_methods: usize,
    /// Maximum number of targets for any virtual method.
    pub max_targets: usize,
    /// Total number of types indexed.
    pub total_types: usize,
    /// Number of interface types.
    pub interface_types: usize,
    /// Number of sealed types.
    pub sealed_types: usize,
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::{
        analysis::callgraph::ResolverStats,
        metadata::{
            signatures::TypeSignature,
            tables::{CodedIndex, CodedIndexType, TableDataOwned, TypeDefRaw},
            validation::ValidationConfig,
        },
        testkit::{
            mono::compilation::compile,
            tools::{require_tool, ToolKind},
        },
    };

    /// Every shape an override or implementation takes: an overload of the overridden
    /// method's name declared before the override, an override of a generic base's method,
    /// an implicit and an explicit interface implementation.
    const HIERARCHY: &str = r#"
public class Shape { public virtual int Area(int scale) { return 0; } }
public class Square : Shape {
    public virtual int Area(string unit) { return 1; }
    public override int Area(int scale) { return 2; }
}
public class Box<T> { public virtual int Size(T item) { return 0; } }
public class IntBox : Box<int> { public override int Size(int item) { return 4; } }
public interface IMeasure { int Measure(); }
public class Ruler : IMeasure { public int Measure() { return 5; } }
public class Tape { public virtual int Measure() { return 7; } }
public class Reel : Tape, IMeasure { }
public interface ICount { int Count(); }
public class Counter : ICount { int ICount.Count() { return 6; } }
public static class Program { public static void Main() { } }
"#;

    /// `HIERARCHY` compiled and loaded, or `None` without a C# compiler.
    fn hierarchy(dir: &TempDir) -> Option<CilObject> {
        let caps = require_tool(ToolKind::Toolchain)?;
        let arch = caps.supported_architectures.first().unwrap();
        let compiled = compile(caps, HIERARCHY, dir.path(), "hierarchy", arch).unwrap();
        assert!(compiled.is_success(), "{:?}", compiled.error);
        Some(CilObject::from_path(compiled.assembly_path()).unwrap())
    }

    /// The method `name` of the type `type_name`, its first parameter `first` when given.
    fn method(
        assembly: &CilObject,
        type_name: &str,
        name: &str,
        first: Option<TypeSignature>,
    ) -> Token {
        assembly
            .methods()
            .iter()
            .map(|entry| entry.value().clone())
            .find(|method| {
                method.name == name
                    && method
                        .declaring_type_rc()
                        .is_some_and(|declaring| declaring.name == type_name)
                    && first.as_ref().is_none_or(|first| {
                        method
                            .signature
                            .params
                            .first()
                            .is_some_and(|param| param.base == *first)
                    })
            })
            .map(|method| method.token)
            .unwrap_or_else(|| panic!("{type_name}::{name}"))
    }

    #[test]
    fn every_override_and_implementation_is_a_target() {
        let dir = TempDir::new().unwrap();
        let Some(assembly) = hierarchy(&dir) else {
            return;
        };
        let resolver = CallResolver::new(&assembly);
        let targets = |token: Token| resolver.resolve_virtual(token);

        let area = method(&assembly, "Shape", "Area", None);
        let override_ = method(&assembly, "Square", "Area", Some(TypeSignature::I4));
        assert!(
            targets(area).contains(&override_),
            "an overload declared before the override hid it"
        );

        let size = method(&assembly, "Box`1", "Size", None);
        let int_size = method(&assembly, "IntBox", "Size", None);
        assert!(
            targets(size).contains(&int_size),
            "an override of a generic base's method"
        );
        assert!(resolver.is_polymorphic(size));

        let measure = method(&assembly, "IMeasure", "Measure", None);
        let ruler = method(&assembly, "Ruler", "Measure", None);
        assert!(
            targets(measure).contains(&ruler),
            "an implicit implementation"
        );
        let tape = method(&assembly, "Tape", "Measure", None);
        assert!(
            targets(measure).contains(&tape),
            "an implementation the implementing type inherits"
        );

        let count = method(&assembly, "ICount", "Count", None);
        let counter = method(&assembly, "Counter", "ICount.Count", None);
        assert!(
            targets(count).contains(&counter),
            "an explicit implementation"
        );
    }

    #[test]
    fn an_inheritance_cycle_ends_the_walk() {
        let dir = TempDir::new().unwrap();
        let Some(assembly) = hierarchy(&dir) else {
            return;
        };
        // Shape extends Square, which extends Shape
        let shape = method(&assembly, "Shape", "Area", None);
        let shape_type = resolver_type(&assembly, shape);
        let square_type = resolver_type(&assembly, method(&assembly, "Square", "Area", None));
        let mut row = assembly
            .tables()
            .and_then(|tables| tables.table::<TypeDefRaw>())
            .and_then(|table| table.get(shape_type.row()).ok().flatten())
            .unwrap();
        row.extends = CodedIndex::new(
            TableId::TypeDef,
            square_type.row(),
            CodedIndexType::TypeDefOrRef,
        );
        let mut cyclic = assembly.into_assembly();
        cyclic
            .table_row_update(
                TableId::TypeDef,
                shape_type.row(),
                TableDataOwned::TypeDef(row),
            )
            .unwrap();
        let cyclic = CilObject::from_mem_with_validation(
            cyclic.to_memory().unwrap(),
            ValidationConfig::analysis(),
        )
        .unwrap();

        let resolver = CallResolver::new(&cyclic);
        assert!(resolver.resolve_virtual(shape).contains(&shape));
    }

    /// The type declaring `method`.
    fn resolver_type(assembly: &CilObject, method: Token) -> Token {
        assembly
            .method(&method)
            .ok()
            .and_then(|method| method.declaring_type_rc())
            .map(|declaring| declaring.token)
            .unwrap()
    }

    #[test]
    fn test_resolver_stats_default() {
        let stats = ResolverStats::default();
        assert_eq!(stats.total_methods, 0);
        assert_eq!(stats.virtual_methods, 0);
        assert_eq!(stats.polymorphic_methods, 0);
    }
}

//! Composable query system for types and methods.
//!
//! This module provides fluent builder-style queries for filtering and searching
//! types and methods in .NET assemblies. Instead of writing manual iteration loops
//! with nested conditionals, queries compose readable filter chains.
//!
//! # Examples
//!
//! ```rust,no_run
//! use dotscope::CilObject;
//!
//! let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
//!
//! // Find all public, defined (non-TypeRef) types
//! let public_types = assembly.query_types()
//!     .defined()
//!     .public()
//!     .find_all();
//!
//! // Find static constructors across the assembly
//! let cctors = assembly.query_methods()
//!     .static_constructors()
//!     .find_all();
//! # Ok::<(), dotscope::Error>(())
//! ```

use crate::metadata::{
    method::{Method, MethodMap, MethodRc, MethodRefList},
    tables::{Field, FieldAttributes, FieldList, FieldRc},
    token::Token,
    typesystem::{CilType, CilTypeRc, TypeRegistry},
};

/// A boxed filter predicate over [`CilType`] references.
type TypeFilter<'a> = Box<dyn Fn(&CilType) -> bool + 'a>;

/// A boxed filter predicate over [`Method`] references.
type MethodFilter<'a> = Box<dyn Fn(&Method) -> bool + 'a>;

/// A boxed filter predicate over [`Field`] references.
type FieldFilter<'a> = Box<dyn Fn(&Field) -> bool + 'a>;

/// A composable query builder for filtering types in an assembly.
///
/// `TypeQuery` holds a reference to the [`TypeRegistry`] and accumulates filter predicates.
/// Each fluent method consumes and returns `Self`, allowing chained calls.
/// Terminal methods like [`TypeQuery::find_all`] execute the query and return results.
pub struct TypeQuery<'a> {
    registry: &'a TypeRegistry,
    filters: Vec<TypeFilter<'a>>,
}

impl<'a> TypeQuery<'a> {
    /// Creates a new `TypeQuery` over the given type registry.
    pub fn new(registry: &'a TypeRegistry) -> Self {
        Self {
            registry,
            filters: Vec::new(),
        }
    }

    /// Filters to types defined in this assembly (excludes external TypeRefs).
    #[must_use]
    pub fn defined(mut self) -> Self {
        self.filters.push(Box::new(|t| !t.is_typeref()));
        self
    }

    /// Filters to class types.
    #[must_use]
    pub fn classes(mut self) -> Self {
        self.filters.push(Box::new(CilType::is_class));
        self
    }

    /// Filters to interface types.
    #[must_use]
    pub fn interfaces(mut self) -> Self {
        self.filters.push(Box::new(CilType::is_interface));
        self
    }

    /// Filters to value types (structs, enums, primitives).
    #[must_use]
    pub fn value_types(mut self) -> Self {
        self.filters.push(Box::new(CilType::is_value_type));
        self
    }

    /// Filters to enum types.
    #[must_use]
    pub fn enums(mut self) -> Self {
        self.filters.push(Box::new(CilType::is_enum));
        self
    }

    /// Filters to delegate types.
    #[must_use]
    pub fn delegates(mut self) -> Self {
        self.filters.push(Box::new(CilType::is_delegate));
        self
    }

    /// Filters to publicly visible types.
    #[must_use]
    pub fn public(mut self) -> Self {
        self.filters.push(Box::new(CilType::is_public));
        self
    }

    /// Filters to internal (assembly-only) types.
    #[must_use]
    pub fn internal(mut self) -> Self {
        self.filters.push(Box::new(CilType::is_internal));
        self
    }

    /// Filters to sealed types.
    #[must_use]
    pub fn sealed(mut self) -> Self {
        self.filters.push(Box::new(CilType::is_sealed));
        self
    }

    /// Filters to abstract types.
    #[must_use]
    pub fn abstract_types(mut self) -> Self {
        self.filters.push(Box::new(CilType::is_abstract));
        self
    }

    /// Filters to types in the exact namespace.
    #[must_use]
    pub fn namespace(mut self, ns: &'a str) -> Self {
        self.filters.push(Box::new(move |t| t.namespace == ns));
        self
    }

    /// Filters to types whose namespace starts with the given prefix.
    #[must_use]
    pub fn namespace_prefix(mut self, prefix: &'a str) -> Self {
        self.filters
            .push(Box::new(move |t| t.namespace.starts_with(prefix)));
        self
    }

    /// Filters to types with the exact name.
    #[must_use]
    pub fn name(mut self, name: &'a str) -> Self {
        self.filters.push(Box::new(move |t| t.name == name));
        self
    }

    /// Filters to types whose name contains the given substring.
    #[must_use]
    pub fn name_contains(mut self, substr: &'a str) -> Self {
        self.filters
            .push(Box::new(move |t| t.name.contains(substr)));
        self
    }

    /// Filters to types whose fullname matches exactly.
    #[must_use]
    pub fn fullname(mut self, fqn: &'a str) -> Self {
        self.filters.push(Box::new(move |t| t.fullname() == fqn));
        self
    }

    /// Filters to types that have at least one method.
    #[must_use]
    pub fn has_methods(mut self) -> Self {
        self.filters.push(Box::new(|t| !t.methods.is_empty()));
        self
    }

    /// Filters to types that have at least one field.
    #[must_use]
    pub fn has_fields(mut self) -> Self {
        self.filters.push(Box::new(|t| !t.fields.is_empty()));
        self
    }

    /// Filters to nested types (have an enclosing type).
    #[must_use]
    pub fn nested(mut self) -> Self {
        self.filters
            .push(Box::new(|t| t.enclosing_type.get().is_some()));
        self
    }

    /// Filters to top-level types (no enclosing type).
    #[must_use]
    pub fn top_level(mut self) -> Self {
        self.filters
            .push(Box::new(|t| t.enclosing_type.get().is_none()));
        self
    }

    /// Filters to types that have a base type.
    #[must_use]
    pub fn has_base_type(mut self) -> Self {
        self.filters.push(Box::new(|t| t.base().is_some()));
        self
    }

    /// Filters to generic types (have generic parameters).
    #[must_use]
    pub fn generic(mut self) -> Self {
        self.filters
            .push(Box::new(|t| !t.generic_params.is_empty()));
        self
    }

    /// Applies a custom filter predicate.
    #[must_use]
    pub fn filter(mut self, f: impl Fn(&CilType) -> bool + 'a) -> Self {
        self.filters.push(Box::new(f));
        self
    }

    /// Returns all matching types.
    #[must_use]
    pub fn find_all(&self) -> Vec<CilTypeRc> {
        self.iter().collect()
    }

    /// Returns the first matching type, short-circuiting iteration.
    #[must_use]
    pub fn find_first(&self) -> Option<CilTypeRc> {
        self.iter().next()
    }

    /// Returns the count of matching types.
    #[must_use]
    pub fn count(&self) -> usize {
        self.iter().count()
    }

    /// Returns `true` if any type matches (short-circuits).
    #[must_use]
    pub fn exists(&self) -> bool {
        self.iter().next().is_some()
    }

    /// Returns just the tokens of matching types.
    #[must_use]
    pub fn tokens(&self) -> Vec<Token> {
        self.iter().map(|t| t.token).collect()
    }

    /// Returns a lazy iterator over matching types.
    pub fn iter(&self) -> impl Iterator<Item = CilTypeRc> + '_ {
        self.registry.iter().filter_map(move |entry| {
            let t = entry.value().clone();
            if self.filters.iter().all(|f| f(&t)) {
                Some(t)
            } else {
                None
            }
        })
    }

    /// Collects methods from all matched types and pivots to a [`MethodQuery`].
    #[must_use]
    pub fn methods(self) -> MethodQuery<'a> {
        let methods: Vec<MethodRc> = self
            .iter()
            .flat_map(|t| {
                t.methods
                    .iter()
                    .filter_map(|(_, method_ref)| method_ref.upgrade())
                    .collect::<Vec<_>>()
            })
            .collect();
        MethodQuery::from_collected(methods)
    }
}

/// Source of methods for a [`MethodQuery`].
enum MethodQuerySource<'a> {
    /// All methods from an assembly's method map.
    Assembly(&'a MethodMap),
    /// Pre-collected methods (from a type or TypeQuery pivot).
    Collected(Vec<MethodRc>),
}

/// A composable query builder for filtering methods.
///
/// `MethodQuery` can be constructed from the assembly's method map or from
/// a pre-collected set of methods (e.g., pivoted from a [`TypeQuery`]).
/// Each fluent method consumes and returns `Self`, allowing chained calls.
pub struct MethodQuery<'a> {
    source: MethodQuerySource<'a>,
    filters: Vec<MethodFilter<'a>>,
}

impl<'a> MethodQuery<'a> {
    /// Creates a `MethodQuery` over all methods in an assembly.
    pub fn from_assembly(methods: &'a MethodMap) -> Self {
        Self {
            source: MethodQuerySource::Assembly(methods),
            filters: Vec::new(),
        }
    }

    /// Creates a `MethodQuery` from a type's method ref list.
    ///
    /// This handles the weak-ref upgrade boilerplate automatically.
    pub fn from_type(methods: &MethodRefList) -> Self {
        let collected: Vec<MethodRc> = methods
            .iter()
            .filter_map(|(_, method_ref)| method_ref.upgrade())
            .collect();
        Self {
            source: MethodQuerySource::Collected(collected),
            filters: Vec::new(),
        }
    }

    /// Creates a `MethodQuery` from a pre-collected vector of methods.
    fn from_collected(methods: Vec<MethodRc>) -> Self {
        Self {
            source: MethodQuerySource::Collected(methods),
            filters: Vec::new(),
        }
    }

    /// Filters to public methods.
    #[must_use]
    pub fn public(mut self) -> Self {
        self.filters.push(Box::new(Method::is_public));
        self
    }

    /// Filters to static methods.
    #[must_use]
    pub fn static_methods(mut self) -> Self {
        self.filters.push(Box::new(Method::is_static));
        self
    }

    /// Filters to instance (non-static) methods.
    #[must_use]
    pub fn instance(mut self) -> Self {
        self.filters.push(Box::new(|m| !m.is_static()));
        self
    }

    /// Filters to virtual methods.
    #[must_use]
    pub fn virtual_methods(mut self) -> Self {
        self.filters.push(Box::new(Method::is_virtual));
        self
    }

    /// Filters to abstract methods.
    #[must_use]
    pub fn abstract_methods(mut self) -> Self {
        self.filters.push(Box::new(Method::is_abstract));
        self
    }

    /// Filters to instance constructors (`.ctor`).
    #[must_use]
    pub fn constructors(mut self) -> Self {
        self.filters.push(Box::new(Method::is_ctor));
        self
    }

    /// Filters to static constructors (`.cctor`).
    #[must_use]
    pub fn static_constructors(mut self) -> Self {
        self.filters.push(Box::new(Method::is_cctor));
        self
    }

    /// Filters to methods with the exact name.
    #[must_use]
    pub fn name(mut self, name: &'a str) -> Self {
        self.filters.push(Box::new(move |m| m.name == name));
        self
    }

    /// Filters to methods whose name contains the given substring.
    #[must_use]
    pub fn name_contains(mut self, substr: &'a str) -> Self {
        self.filters
            .push(Box::new(move |m| m.name.contains(substr)));
        self
    }

    /// Filters to methods that have a parsed body.
    #[must_use]
    pub fn has_body(mut self) -> Self {
        self.filters.push(Box::new(Method::has_body));
        self
    }

    /// Filters to methods without a parsed body.
    #[must_use]
    pub fn without_body(mut self) -> Self {
        self.filters.push(Box::new(|m| !m.has_body()));
        self
    }

    /// Filters to methods with native code implementation.
    #[must_use]
    pub fn native(mut self) -> Self {
        self.filters.push(Box::new(Method::is_code_native));
        self
    }

    /// Filters to methods with IL code implementation.
    #[must_use]
    pub fn il(mut self) -> Self {
        self.filters.push(Box::new(Method::is_code_il));
        self
    }

    /// Filters to P/Invoke methods.
    #[must_use]
    pub fn pinvoke(mut self) -> Self {
        self.filters.push(Box::new(Method::is_pinvoke));
        self
    }

    /// Filters to methods with at least `n` parameters.
    #[must_use]
    pub fn min_params(mut self, n: usize) -> Self {
        self.filters
            .push(Box::new(move |m| m.signature.params.len() >= n));
        self
    }

    /// Filters to methods with at most `n` parameters.
    #[must_use]
    pub fn max_params(mut self, n: usize) -> Self {
        self.filters
            .push(Box::new(move |m| m.signature.params.len() <= n));
        self
    }

    /// Filters to methods whose declaring type fullname matches.
    #[must_use]
    pub fn declaring_type(mut self, type_name: &'a str) -> Self {
        self.filters.push(Box::new(move |m| {
            m.declaring_type_fullname().is_some_and(|n| n == type_name)
        }));
        self
    }

    /// Filters to event handler methods.
    #[must_use]
    pub fn event_handlers(mut self) -> Self {
        self.filters.push(Box::new(Method::is_event_handler));
        self
    }

    /// Applies a custom filter predicate.
    #[must_use]
    pub fn filter(mut self, f: impl Fn(&Method) -> bool + 'a) -> Self {
        self.filters.push(Box::new(f));
        self
    }

    /// Returns all matching methods.
    #[must_use]
    pub fn find_all(&self) -> Vec<MethodRc> {
        self.iter().collect()
    }

    /// Returns the first matching method, short-circuiting iteration.
    #[must_use]
    pub fn find_first(&self) -> Option<MethodRc> {
        self.iter().next()
    }

    /// Returns the count of matching methods.
    #[must_use]
    pub fn count(&self) -> usize {
        self.iter().count()
    }

    /// Returns `true` if any method matches (short-circuits).
    #[must_use]
    pub fn exists(&self) -> bool {
        self.iter().next().is_some()
    }

    /// Returns just the tokens of matching methods.
    #[must_use]
    pub fn tokens(&self) -> Vec<Token> {
        self.iter().map(|m| m.token).collect()
    }

    /// Returns a lazy iterator over matching methods.
    pub fn iter(&self) -> Box<dyn Iterator<Item = MethodRc> + '_> {
        let base: Box<dyn Iterator<Item = MethodRc> + '_> = match &self.source {
            MethodQuerySource::Assembly(map) => {
                Box::new(map.iter().map(|entry| entry.value().clone()))
            }
            MethodQuerySource::Collected(methods) => Box::new(methods.iter().cloned()),
        };

        Box::new(base.filter(move |m| self.filters.iter().all(|f| f(m))))
    }
}

impl<'b> IntoIterator for &'b MethodQuery<'_> {
    type Item = MethodRc;
    type IntoIter = Box<dyn Iterator<Item = MethodRc> + 'b>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// A composable query builder for filtering fields in a type.
///
/// Mirrors the [`MethodQuery`] pattern: fluent filter chains with
/// terminal methods like [`find_all`](Self::find_all) and [`find_first`](Self::find_first).
pub struct FieldQuery<'a> {
    fields: &'a FieldList,
    filters: Vec<FieldFilter<'a>>,
}

impl<'a> FieldQuery<'a> {
    /// Creates a `FieldQuery` over a type's field list.
    pub fn from_type(fields: &'a FieldList) -> Self {
        Self {
            fields,
            filters: Vec::new(),
        }
    }

    /// Filters to static fields.
    #[must_use]
    pub fn static_fields(mut self) -> Self {
        self.filters.push(Box::new(|f| f.flags.is_static()));
        self
    }

    /// Filters to instance (non-static) fields.
    #[must_use]
    pub fn instance_fields(mut self) -> Self {
        self.filters.push(Box::new(|f| !f.flags.is_static()));
        self
    }

    /// Filters to public fields.
    #[must_use]
    pub fn public(mut self) -> Self {
        self.filters
            .push(Box::new(|f| f.flags.access() == FieldAttributes::PUBLIC));
        self
    }

    /// Filters to fields with the exact name.
    #[must_use]
    pub fn name(mut self, name: &'a str) -> Self {
        self.filters.push(Box::new(move |f| f.name == name));
        self
    }

    /// Applies a custom filter predicate.
    #[must_use]
    pub fn filter(mut self, f: impl Fn(&Field) -> bool + 'a) -> Self {
        self.filters.push(Box::new(f));
        self
    }

    /// Returns all matching fields.
    #[must_use]
    pub fn find_all(&self) -> Vec<FieldRc> {
        self.iter().collect()
    }

    /// Returns the first matching field, short-circuiting iteration.
    #[must_use]
    pub fn find_first(&self) -> Option<FieldRc> {
        self.iter().next()
    }

    /// Returns the count of matching fields.
    #[must_use]
    pub fn count(&self) -> usize {
        self.iter().count()
    }

    /// Returns `true` if any field matches (short-circuits).
    #[must_use]
    pub fn exists(&self) -> bool {
        self.iter().next().is_some()
    }

    /// Returns just the tokens of matching fields.
    #[must_use]
    pub fn tokens(&self) -> Vec<Token> {
        self.iter().map(|f| f.token).collect()
    }

    /// Returns a lazy iterator over matching fields.
    pub fn iter(&self) -> impl Iterator<Item = FieldRc> + '_ {
        self.fields.iter().filter_map(move |(_, field)| {
            if self.filters.iter().all(|f| f(field)) {
                Some(field.clone())
            } else {
                None
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{testkit::fixture, CilObject};

    #[test]
    fn test_type_query_defined_filters_typerefs() {
        let assembly =
            CilObject::from_path(fixture("WindowsBase.dll")).expect("Failed to load assembly");

        let all_types = assembly.types().all_types();
        let defined_types = assembly.query_types().defined().find_all();

        // Defined types should be fewer than all types (which include TypeRefs)
        assert!(defined_types.len() < all_types.len());
        // All defined types should not be TypeRefs
        assert!(defined_types.iter().all(|t| !t.is_typeref()));
    }

    #[test]
    fn test_type_query_chained_filters() {
        let assembly =
            CilObject::from_path(fixture("WindowsBase.dll")).expect("Failed to load assembly");

        let public_defined = assembly.query_types().defined().public().find_all();

        // All results should be both defined and public
        for t in &public_defined {
            assert!(!t.is_typeref());
            assert!(t.is_public());
        }
    }

    #[test]
    fn test_type_query_exists_and_count() {
        let assembly =
            CilObject::from_path(fixture("WindowsBase.dll")).expect("Failed to load assembly");

        assert!(assembly.query_types().defined().exists());
        assert!(assembly.query_types().defined().count() > 0);
    }

    #[test]
    fn test_method_query_from_assembly() {
        let assembly =
            CilObject::from_path(fixture("WindowsBase.dll")).expect("Failed to load assembly");

        let static_methods = assembly.query_methods().static_methods().find_all();
        assert!(!static_methods.is_empty());
        assert!(static_methods.iter().all(|m| m.is_static()));
    }

    #[test]
    fn test_method_query_static_constructors() {
        let assembly =
            CilObject::from_path(fixture("WindowsBase.dll")).expect("Failed to load assembly");

        let cctors = assembly.query_methods().static_constructors().find_all();
        assert!(cctors.iter().all(|m| m.is_cctor()));
    }

    #[test]
    fn test_type_query_methods_pivot() {
        let assembly =
            CilObject::from_path(fixture("WindowsBase.dll")).expect("Failed to load assembly");

        // Get public methods from defined public types
        let methods = assembly
            .query_types()
            .defined()
            .public()
            .methods()
            .public()
            .find_all();

        assert!(!methods.is_empty());
        assert!(methods.iter().all(|m| m.is_public()));
    }

    #[test]
    fn test_method_query_by_name() {
        let assembly =
            CilObject::from_path(fixture("WindowsBase.dll")).expect("Failed to load assembly");

        let ctors = assembly.query_methods().name(".ctor").find_all();
        assert!(!ctors.is_empty());
        assert!(ctors.iter().all(|m| m.name == ".ctor"));
    }

    #[test]
    fn test_type_query_tokens() {
        let assembly =
            CilObject::from_path(fixture("WindowsBase.dll")).expect("Failed to load assembly");

        let tokens = assembly.query_types().defined().public().tokens();
        let types = assembly.query_types().defined().public().find_all();

        assert_eq!(tokens.len(), types.len());
    }

    #[test]
    fn test_type_query_from_type_methods() {
        let assembly =
            CilObject::from_path(fixture("WindowsBase.dll")).expect("Failed to load assembly");

        // Find a type that has methods, then query its methods
        let type_opt = assembly.query_types().defined().has_methods().find_first();
        if let Some(t) = type_opt {
            let methods = t.query_methods().find_all();
            assert!(!methods.is_empty());
        }
    }
}

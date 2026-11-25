//! Virtual and interface method dispatch resolution.
//!
//! This module implements ECMA-335 §II.12.2 method dispatch for `callvirt`
//! instructions. The [`DispatchResolver`] resolves a declared (base) method
//! token to the most-derived concrete implementation given the runtime type
//! of the `this` object.
//!
//! # Resolution Algorithm
//!
//! Two dispatch paths are supported, selected by whether the declaring type
//! of the base method is an interface:
//!
//! ## Class Virtual Dispatch
//!
//! Walks the runtime type's inheritance chain (most-derived first) looking
//! for a method with the same name, `virtual` flag, and compatible signature.
//! This matches CoreCLR's `MethodTable::FindDispatchSlotForInterface` /
//! Mono's `mono_method_get_vtable_slot` behavior.
//!
//! ## Interface Dispatch
//!
//! Follows ECMA-335 §II.12.2 in three steps:
//! 1. **Explicit MethodImpl** — each method on the runtime type (and its
//!    bases) is checked for an `overrides` entry pointing at the interface
//!    method token.
//! 2. **Implicit name+signature match** — the runtime type's methods are
//!    scanned for a non-static method with the same name and compatible
//!    parameter types.
//! 3. **Base type walk** — if neither check matches, the algorithm recurses
//!    on the base type.
//!
//! # Caching
//!
//! Both dispatch paths cache their results in a lock-free [`DashMap`] keyed
//! by `(runtime_type_token, declared_method_token)`. After the first
//! resolution, subsequent calls for the same pair are O(1).
//!
//! # Usage
//!
//! ```text
//! let resolver = DispatchResolver::new();
//! let concrete = resolver.resolve(declared_method, runtime_type, &context);
//! // concrete == declared_method if no override exists
//! ```

use std::collections::HashMap;

use dashmap::DashMap;

use crate::{
    emulation::engine::context::EmulationContext,
    metadata::{
        method::Method,
        signatures::SignatureMethod,
        tables::{MemberRefSignature, TableId},
        token::Token,
        typesystem::{CilType, CilTypeReference},
    },
};

/// Pre-computed virtual method table for a concrete type.
///
/// Maps each virtual/interface method slot to its concrete implementation.
/// Built lazily on first dispatch for a type, then all subsequent dispatches
/// for any method on that type are O(1) hash lookups.
struct VTable {
    /// `declared_method → concrete_implementation` slots.
    slots: HashMap<Token, Token>,
}

/// Caches and resolves virtual and interface method dispatch.
///
/// Constructed once by the [`EmulationController`](super::controller::EmulationController)
/// and shared for the lifetime of the emulation process. Resolution results
/// are cached in a lock-free [`DashMap`] so repeated `callvirt` on the same
/// `(runtime_type, declared_method)` pair costs only a hash lookup.
///
/// # Thread Safety
///
/// `DispatchResolver` is `Send + Sync` — the inner [`DashMap`] uses sharded
/// locking for concurrent reads and writes without external synchronization.
pub struct DispatchResolver {
    /// Cache: `(runtime_type, declared_method) → resolved_method`.
    ///
    /// Populated lazily on first resolution; never evicted. For typical
    /// emulation workloads (thousands of unique call sites) the map stays
    /// small relative to available memory.
    cache: DashMap<(Token, Token), Token>,

    /// Pre-computed VTables keyed by runtime type token.
    ///
    /// Built lazily on first dispatch for a type. Once built, all virtual
    /// method lookups for that type are O(1).
    vtables: DashMap<Token, VTable>,
}

/// Deepest inheritance chain the dispatch walkers will follow.
///
/// These walk `base()` to the root and are tail-recursive, which Rust does not
/// guarantee to turn into a loop. `CilType::set_base` deliberately permits a
/// cyclic chain — a dedicated validator reports it as a finding rather than
/// refusing to represent it — so a corrupt assembly whose TypeDefs extend each
/// other reaches these with no terminating condition.
const MAX_BASE_WALK_DEPTH: usize = 256;

impl DispatchResolver {
    /// Creates a new empty resolver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: DashMap::new(),
            vtables: DashMap::new(),
        }
    }

    /// Resolves a virtual or interface method call to a concrete implementation.
    ///
    /// Given the declared method token and the runtime type of the `this` object,
    /// walks the type hierarchy to find the most-derived override. Non-virtual
    /// methods and unresolvable types are returned unchanged.
    ///
    /// Results are cached for O(1) repeated lookups with the same
    /// `(runtime_type, declared_method)` pair.
    ///
    /// # Arguments
    ///
    /// * `declared_method` — Token of the method as declared in the `callvirt`
    ///   instruction (may be abstract or on a base type).
    /// * `runtime_type` — Token of the actual runtime type of the `this` object,
    ///   obtained from the heap via `get_type_token()`.
    /// * `context` — Emulation context for accessing assembly metadata (type
    ///   hierarchy, method signatures, interface implementations).
    ///
    /// # Returns
    ///
    /// The token of the concrete method to invoke. This is either:
    /// - The most-derived override found in the runtime type's hierarchy, or
    /// - The original `declared_method` if no override exists or the type cannot
    ///   be resolved.
    #[must_use]
    pub fn resolve(
        &self,
        declared_method: Token,
        runtime_type: Token,
        context: &EmulationContext,
    ) -> Token {
        let key = (runtime_type, declared_method);

        // Cache hit (per-pair cache)
        if let Some(cached) = self.cache.get(&key) {
            return *cached;
        }

        // VTable hit — check if we already have a pre-computed VTable for this type
        if let Some(vtable) = self.vtables.get(&runtime_type) {
            if let Some(&resolved) = vtable.slots.get(&declared_method) {
                self.cache.insert(key, resolved);
                return resolved;
            }
        }

        // Resolve the method: a MemberRef names a method of another assembly (a BCL virtual
        // or interface method), whose override in the runtime type is found by its name
        // and signature
        let Ok(method) = context.get_method(declared_method) else {
            if !declared_method.is_table(TableId::MemberRef) {
                return declared_method;
            }
            let resolved = Self::resolve_member_ref(declared_method, runtime_type, context);
            self.cache.insert(key, resolved);
            return resolved;
        };

        if !method.is_virtual() {
            return declared_method;
        }

        // Get declaring type to check if it's an interface
        let is_interface_call = method
            .declaring_type_rc()
            .is_some_and(|dt| dt.is_interface());

        let resolved = if is_interface_call {
            self.resolve_interface(runtime_type, declared_method, &method, context)
        } else {
            self.resolve_virtual(runtime_type, &method, context)
        };

        self.cache.insert(key, resolved);
        resolved
    }

    /// Resolves a call of a method another assembly declares, named by a MemberRef, to the
    /// runtime type's implementation of it.
    ///
    /// ECMA-335 II.10.3: the runtime type, or the nearest base type that has one, provides
    /// the method either explicitly, through a MethodImpl naming the MemberRef, or by a
    /// virtual instance method of the same name and signature. A type that provides neither
    /// inherits the declared method, and the MemberRef is returned unchanged.
    fn resolve_member_ref(
        declared: Token,
        runtime_type: Token,
        context: &EmulationContext,
    ) -> Token {
        let Some(member_ref) = context.get_member_ref(declared) else {
            return declared;
        };
        let MemberRefSignature::Method(signature) = &member_ref.signature else {
            return declared;
        };
        if !signature.has_this {
            return declared;
        }
        let Some(runtime) = context.assembly().types().resolve(&runtime_type) else {
            return declared;
        };
        Self::find_member_ref_override(0, &runtime, declared, &member_ref.name, signature)
            .unwrap_or(declared)
    }

    /// Searches a type and its bases for the implementation of the method the MemberRef
    /// `member_ref` names: a method whose MethodImpl names it, else a virtual instance method
    /// named `name` with the parameters of `signature`.
    fn find_member_ref_override(
        depth: usize,
        type_info: &CilType,
        member_ref: Token,
        name: &str,
        signature: &SignatureMethod,
    ) -> Option<Token> {
        if depth >= MAX_BASE_WALK_DEPTH {
            return None;
        }
        let methods: Vec<_> = type_info
            .methods
            .iter()
            .filter_map(|(_, method_ref)| method_ref.upgrade())
            .collect();
        let explicit = methods.iter().find(|method| {
            method.overrides.iter().any(|(_, override_ref)| {
                matches!(override_ref, CilTypeReference::MemberRef(rc) if rc.token == member_ref)
            })
        });
        if let Some(method) = explicit {
            return Some(method.token);
        }
        let implicit = methods.iter().find(|method| {
            method.is_virtual()
                && !method.is_static()
                && method.name == name
                && method.signature.has_same_parameters(signature)
        });
        if let Some(method) = implicit {
            return Some(method.token);
        }
        let base = type_info.base()?;
        Self::find_member_ref_override(depth.saturating_add(1), &base, member_ref, name, signature)
    }

    /// Resolves an interface method call to a concrete implementation.
    fn resolve_interface(
        &self,
        runtime_type: Token,
        interface_method: Token,
        base_method: &Method,
        context: &EmulationContext,
    ) -> Token {
        let Some(rt) = context.assembly().types().resolve(&runtime_type) else {
            return interface_method;
        };

        if let Some(found) = Self::find_interface_impl(0, &rt, interface_method, base_method) {
            return found;
        }

        // Step 4: Default Interface Methods (DIM) — if the interface method itself
        // has a body and is not abstract, it serves as the default implementation.
        if base_method.has_body() && !base_method.is_abstract() {
            return interface_method;
        }

        interface_method
    }

    /// Searches a type (and its bases) for an implementation of an interface method.
    ///
    /// Per ECMA-335 §II.12.2:
    /// 1. Explicit MethodImpl — check each method's `overrides` for the interface method token
    /// 2. Implicit name+signature match — find method with same name and compatible signature
    ///    (skipping methods that explicitly override a DIFFERENT interface method)
    /// 3. Walk base types — recurse on the base type
    fn find_interface_impl(
        depth: usize,
        type_info: &CilType,
        interface_method: Token,
        base_method: &Method,
    ) -> Option<Token> {
        if depth >= MAX_BASE_WALK_DEPTH {
            return None;
        }
        // Step 1: Explicit MethodImpl — check each method's overrides list
        for (_, method_ref) in type_info.methods.iter() {
            let Some(method) = method_ref.upgrade() else {
                continue;
            };
            for (_, override_ref) in method.overrides.iter() {
                let override_token = match override_ref {
                    CilTypeReference::MethodDef(weak) => weak.upgrade().map(|m| m.token),
                    CilTypeReference::MemberRef(rc) => Some(rc.token),
                    _ => None,
                };
                if override_token == Some(interface_method) {
                    return Some(method.token);
                }
            }
        }

        // Step 2: Implicit name+signature match
        let method_name = &base_method.name;
        for (_, method_ref) in type_info.methods.iter() {
            let Some(method) = method_ref.upgrade() else {
                continue;
            };
            if method.name != *method_name
                || method.is_static()
                || !method.signature.has_same_parameters(&base_method.signature)
            {
                continue;
            }

            // Skip methods that have explicit MethodImpl overrides for a
            // DIFFERENT interface method. This prevents picking the wrong implicit
            // match when a type implements two interfaces with the same method name.
            let has_conflicting_override = method.overrides.iter().any(|(_, override_ref)| {
                let override_token = match override_ref {
                    CilTypeReference::MethodDef(weak) => weak.upgrade().map(|m| m.token),
                    CilTypeReference::MemberRef(rc) => Some(rc.token),
                    _ => None,
                };
                override_token.is_some() && override_token != Some(interface_method)
            });
            if has_conflicting_override {
                continue;
            }

            return Some(method.token);
        }

        // Step 3: Walk base types
        if let Some(base) = type_info.base() {
            return Self::find_interface_impl(
                depth.saturating_add(1),
                &base,
                interface_method,
                base_method,
            );
        }

        None
    }

    /// Resolves a class virtual method call to the most-derived override.
    fn resolve_virtual(
        &self,
        runtime_type: Token,
        base_method: &Method,
        context: &EmulationContext,
    ) -> Token {
        let Some(rt) = context.assembly().types().resolve(&runtime_type) else {
            return base_method.token;
        };

        if let Some(found) = Self::find_virtual_override(0, &rt, &base_method.name, base_method) {
            return found;
        }

        base_method.token
    }

    /// Finds a virtual method override in a type hierarchy.
    fn find_virtual_override(
        depth: usize,
        type_info: &CilType,
        method_name: &str,
        base_method: &Method,
    ) -> Option<Token> {
        if depth >= MAX_BASE_WALK_DEPTH {
            return None;
        }
        for (_, method_ref) in type_info.methods.iter() {
            let Some(method) = method_ref.upgrade() else {
                continue;
            };
            if method.is_virtual()
                && method.name == method_name
                && method.signature.has_same_parameters(&base_method.signature)
            {
                return Some(method.token);
            }
        }

        // Walk base types
        if let Some(base) = type_info.base() {
            return Self::find_virtual_override(
                depth.saturating_add(1),
                &base,
                method_name,
                base_method,
            );
        }

        None
    }

    /// Pre-computes the VTable for a runtime type, populating all virtual and
    /// interface method slots at once.
    ///
    /// After this call, all subsequent dispatches for this type use O(1)
    /// hash lookups instead of walking the type hierarchy.
    ///
    /// # Arguments
    ///
    /// * `runtime_type` — Token of the concrete runtime type.
    /// * `context` — Emulation context for assembly metadata access.
    pub fn precompute_vtable(&self, runtime_type: Token, context: &EmulationContext) {
        if self.vtables.contains_key(&runtime_type) {
            return;
        }

        let Some(rt) = context.assembly().types().resolve(&runtime_type) else {
            return;
        };

        let mut slots = HashMap::new();

        // Collect all virtual methods from the type hierarchy (most-derived first)
        Self::collect_virtual_slots(0, &rt, &mut slots);

        // Collect interface implementations
        Self::collect_interface_slots(0, &rt, &mut slots);

        self.vtables.insert(runtime_type, VTable { slots });
    }

    /// Collects virtual method slots from a type's inheritance chain.
    fn collect_virtual_slots(depth: usize, type_info: &CilType, slots: &mut HashMap<Token, Token>) {
        if depth >= MAX_BASE_WALK_DEPTH {
            return;
        }
        // Walk base types first (root → derived) so derived overrides win
        if let Some(base) = type_info.base() {
            Self::collect_virtual_slots(depth.saturating_add(1), &base, slots);
        }

        // Override slots for virtual methods on this type
        for (_, method_ref) in type_info.methods.iter() {
            let Some(method) = method_ref.upgrade() else {
                continue;
            };
            if !method.is_virtual() {
                continue;
            }

            // The method itself is the implementation for its own token
            slots.insert(method.token, method.token);

            // Also check overrides
            for (_, override_ref) in method.overrides.iter() {
                let override_token = match override_ref {
                    CilTypeReference::MethodDef(weak) => weak.upgrade().map(|m| m.token),
                    CilTypeReference::MemberRef(rc) => Some(rc.token),
                    _ => None,
                };
                if let Some(ot) = override_token {
                    slots.insert(ot, method.token);
                }
            }
        }
    }

    /// Collects interface method implementations for a type.
    fn collect_interface_slots(
        depth: usize,
        type_info: &CilType,
        slots: &mut HashMap<Token, Token>,
    ) {
        if depth >= MAX_BASE_WALK_DEPTH {
            return;
        }
        // For each interface the type implements, resolve all methods
        for (_, iface_entry) in type_info.interfaces.iter() {
            let Some(iface_type) = iface_entry.interface.upgrade() else {
                continue;
            };

            for (_, iface_method_ref) in iface_type.methods.iter() {
                let Some(iface_method) = iface_method_ref.upgrade() else {
                    continue;
                };

                // Already resolved?
                if slots.contains_key(&iface_method.token) {
                    continue;
                }

                // Try to find implementation
                if let Some(impl_token) =
                    Self::find_interface_impl(0, type_info, iface_method.token, &iface_method)
                {
                    slots.insert(iface_method.token, impl_token);
                } else if iface_method.has_body() && !iface_method.is_abstract() {
                    // Default Interface Method
                    slots.insert(iface_method.token, iface_method.token);
                }
            }
        }

        // Recurse into base type for inherited interface implementations
        if let Some(base) = type_info.base() {
            Self::collect_interface_slots(depth.saturating_add(1), &base, slots);
        }
    }
}

impl Default for DispatchResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::emulation::engine::dispatch::DispatchResolver;

    #[test]
    fn test_resolver_creation() {
        let resolver = DispatchResolver::new();
        assert!(resolver.cache.is_empty());
    }
}

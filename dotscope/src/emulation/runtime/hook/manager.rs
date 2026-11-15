//! Hook manager for registering and executing hooks.
//!
//! This module provides [`HookManager`], which maintains a two-tier indexed collection
//! of hooks for efficient method interception during emulation.
//!
//! # Architecture
//!
//! The hook manager uses a two-tier lookup strategy to minimize per-call overhead:
//!
//! ```text
//!                     Method Call
//!                          │
//!                     ┌────▼────┐
//!                     │ Tier 1  │  DashMap + nested HashMap lookups (zero allocation)
//!                     │  Index  │  namespace → type → method → candidates
//!                     └────┬────┘
//!                          │ hit → Evaluate remaining matchers on small candidate set
//!                          │ miss
//!                     ┌────▼────┐
//!                     │ Tier 2  │  RwLock<Vec<HookEntry>> — wildcard/non-name hooks
//!                     │Fallback │  Linear scan (typically empty)
//!                     └─────────┘
//! ```
//!
//! For the ~95% of method calls that don't match any hook, the cost drops from
//! O(N) matcher evaluations (where N ≈ 120+ registered hooks) to a single O(1)
//! hash lookup + miss, with zero heap allocations on the lookup path.
//!
//! # Thread Safety
//!
//! `HookManager` is internally thread-safe. All methods take `&self`. The name-based
//! indices use [`DashMap`] for lock-free concurrent reads, while wildcard hooks use
//! an [`RwLock`] to support future hook removal. Registration and dispatch never
//! block each other on the common (name-indexed) path.

use std::{
    cmp::Reverse,
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, RwLock,
    },
};

use dashmap::DashMap;

use crate::{
    emulation::{
        runtime::hook::{
            core::Hook,
            types::{HookContext, HookOutcome, PostHookResult, PreHookResult},
        },
        EmValue, EmulationError, EmulationThread,
    },
    Result,
};

/// Nested index mapping type names to their method-level hook entries.
type TypeMethodHookIndex = HashMap<Arc<str>, HashMap<Arc<str>, Vec<HookEntry>>>;

/// Internal routing key extracted from a hook's name-based matchers at registration
/// time. Determines which index tier the hook is placed in.
///
/// Hooks are routed to the most specific index possible:
/// - Full (namespace + type + method) → `full_index` for O(1) exact-match lookup
/// - TypeLevel (namespace + type) → `type_index` for type-scoped hooks
/// - MethodOnly (method name) → `method_index` for cross-type method hooks
/// - No route → `wildcard_hooks` fallback (linear scan)
enum IndexRoute {
    /// Namespace + type + method specified → `full_index`.
    Full(Arc<str>, Arc<str>, Arc<str>),
    /// Namespace + type specified (any method) → `type_index`.
    TypeLevel(Arc<str>, Arc<str>),
    /// Method name only (any namespace/type) → `method_index`.
    MethodOnly(Arc<str>),
}

/// A hook entry in the index, bundling the hook with pre-computed flags about
/// its matcher requirements.
///
/// The hook is wrapped in [`Arc`] so that [`HookManager::find_matching`] can
/// return an owned handle without holding any index guard during hook execution.
/// This decouples the index lookup lifetime from the hook execution lifetime.
///
/// The pre-computed flags (`has_runtime_matchers`, `has_signature_matchers`) enable
/// a fast path in the full-index tier: hooks with exactly one name-only matcher
/// are guaranteed matches once found in the index, skipping redundant evaluation.
struct HookEntry {
    /// The hook itself, wrapped in `Arc` for cheap cloning on match.
    hook: Arc<Hook>,
    /// `true` if any matcher inspects runtime argument values.
    has_runtime_matchers: bool,
    /// `true` if any matcher checks parameter/return type signatures.
    has_signature_matchers: bool,
}

impl HookEntry {
    /// Creates a new entry from a hook, pre-computing matcher flags by scanning
    /// all matchers once at registration time.
    fn new(hook: Hook) -> Self {
        let has_runtime = hook.matchers().iter().any(|m| m.is_runtime_matcher());
        let has_signature = hook.matchers().iter().any(|m| m.is_signature_matcher());
        Self {
            hook: Arc::new(hook),
            has_runtime_matchers: has_runtime,
            has_signature_matchers: has_signature,
        }
    }
}

/// Inspects a hook's matchers and extracts an [`IndexRoute`] for placement.
///
/// Scans the hook's matchers for the first one that provides
/// [`name_components`](crate::emulation::runtime::hook::matcher::HookMatcher::name_components)
/// and maps the returned (namespace, type, method) tuple to the appropriate route.
/// Returns `None` if no name-based matcher exists (hook goes to wildcard bucket).
fn extract_route(hook: &Hook) -> Option<IndexRoute> {
    for matcher in hook.matchers() {
        if let Some((ns, ty, method)) = matcher.name_components() {
            return match (ns, ty, method) {
                (Some(ns), Some(ty), Some(m)) => {
                    Some(IndexRoute::Full(ns.into(), ty.into(), m.into()))
                }
                (Some(ns), Some(ty), None) => Some(IndexRoute::TypeLevel(ns.into(), ty.into())),
                (_, _, Some(m)) => Some(IndexRoute::MethodOnly(m.into())),
                _ => None,
            };
        }
    }
    None
}

/// Pushes an entry into a priority-sorted bucket and re-sorts by descending
/// priority so that higher-priority hooks are checked first during dispatch.
fn insert_sorted(bucket: &mut Vec<HookEntry>, entry: HookEntry) {
    bucket.push(entry);
    bucket.sort_by_key(|e| Reverse(e.hook.priority()));
}

/// Manager for registering and executing hooks.
///
/// The `HookManager` maintains a two-tier indexed collection of hooks for efficient
/// method interception. When a method call is intercepted, the manager uses
/// [`DashMap`]-backed indices to find candidate hooks in O(1) with zero heap
/// allocations, then evaluates remaining matchers on the small candidate set.
///
/// All methods take `&self` — the manager is internally thread-safe.
///
/// # Hook Resolution
///
/// When looking for a matching hook:
///
/// 1. The full index is checked for exact matches (namespace + type + method)
/// 2. Then type-level index (namespace + type, any method)
/// 3. Then method-only index (any type with that method name)
/// 4. Finally, wildcard hooks with no name-based matchers
/// 5. Within each bucket, hooks are checked in priority order (highest first)
/// 6. The first hook whose matchers all match is selected
///
/// # Examples
///
/// ```no_run
/// use dotscope::emulation::{HookManager, Hook, HookPriority, PreHookResult, EmValue};
///
/// let manager = HookManager::new();
///
/// // Register hooks (order doesn't matter, they're sorted by priority)
/// manager.register(
///     Hook::new("low-priority")
///         .with_priority(HookPriority::LOW)
///         .match_method_name("Decrypt")
///         .pre(|ctx, thread| PreHookResult::Continue)
/// )?;
///
/// manager.register(
///     Hook::new("high-priority")
///         .with_priority(HookPriority::HIGH)
///         .match_method_name("Decrypt")
///         .pre(|ctx, thread| PreHookResult::Bypass(Some(EmValue::I32(42))))
/// )?;
///
/// // When "Decrypt" is called, "high-priority" matches first
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct HookManager {
    /// Full match index: namespace → type → method → entries.
    full_index: DashMap<Arc<str>, TypeMethodHookIndex>,

    /// Type-level index: namespace → type → entries.
    type_index: DashMap<Arc<str>, HashMap<Arc<str>, Vec<HookEntry>>>,

    /// Method-only index: method name → entries.
    method_index: DashMap<Arc<str>, Vec<HookEntry>>,

    /// Fallback: hooks with no name-based matchers (runtime-only, signature-only).
    /// Uses `RwLock<Vec>` to support future hook removal.
    wildcard_hooks: RwLock<Vec<HookEntry>>,

    /// Total registered hook count.
    total_count: AtomicUsize,
}

impl Default for HookManager {
    fn default() -> Self {
        Self {
            full_index: DashMap::new(),
            type_index: DashMap::new(),
            method_index: DashMap::new(),
            wildcard_hooks: RwLock::new(Vec::new()),
            total_count: AtomicUsize::new(0),
        }
    }
}

impl HookManager {
    /// Creates a new, empty hook manager.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a hook.
    ///
    /// The hook is indexed by its name-based matcher components for O(1) lookup.
    /// Hooks within each index bucket are automatically sorted by priority (highest
    /// first). Hooks without name-based matchers are placed in a wildcard bucket
    /// that is checked on every call.
    ///
    /// # Arguments
    ///
    /// * `hook` - The hook to register
    ///
    /// # Errors
    ///
    /// Returns an error if the internal wildcard lock is poisoned.
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::emulation::{Hook, HookManager};
    ///
    /// let manager = HookManager::new();
    /// manager.register(Hook::new("my-hook").match_method_name("Test"))?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn register(&self, hook: Hook) -> Result<()> {
        let route = extract_route(&hook);
        let entry = HookEntry::new(hook);

        match route {
            Some(IndexRoute::Full(ns, ty, method)) => {
                let mut ns_map = self.full_index.entry(ns).or_default();
                let bucket = ns_map.entry(ty).or_default().entry(method).or_default();
                insert_sorted(bucket, entry);
            }
            Some(IndexRoute::TypeLevel(ns, ty)) => {
                let mut ns_map = self.type_index.entry(ns).or_default();
                let bucket = ns_map.entry(ty).or_default();
                insert_sorted(bucket, entry);
            }
            Some(IndexRoute::MethodOnly(method)) => {
                let mut bucket = self.method_index.entry(method).or_default();
                insert_sorted(&mut bucket, entry);
            }
            None => {
                let mut wildcards =
                    self.wildcard_hooks
                        .write()
                        .map_err(|_| EmulationError::LockPoisoned {
                            description: "hook manager",
                        })?;
                insert_sorted(&mut wildcards, entry);
            }
        }

        self.total_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Checks whether any hook could potentially match the given name components.
    ///
    /// This is a fast O(1) check that only consults the name indices, without
    /// evaluating any matchers or allocating any heap memory. Used by the
    /// controller to skip full context building when no hook can possibly match.
    ///
    /// Returns `true` if there is at least one hook indexed under any key that
    /// matches the given names, or if wildcard hooks exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the internal wildcard lock is poisoned.
    pub fn has_potential_match(
        &self,
        namespace: &str,
        type_name: &str,
        method_name: &str,
    ) -> Result<bool> {
        let wildcards = self
            .wildcard_hooks
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "hook manager",
            })?;
        if !wildcards.is_empty() {
            return Ok(true);
        }
        drop(wildcards);

        if let Some(type_map) = self.full_index.get(namespace) {
            if let Some(method_map) = type_map.get(type_name) {
                if method_map.contains_key(method_name) {
                    return Ok(true);
                }
            }
        }

        if let Some(type_map) = self.type_index.get(namespace) {
            if type_map.contains_key(type_name) {
                return Ok(true);
            }
        }

        Ok(self.method_index.contains_key(method_name))
    }

    /// Executes a method call through the hook system.
    ///
    /// This is the primary entry point for hook execution. It handles the complete
    /// hook lifecycle:
    ///
    /// 1. Find a matching hook (by priority order)
    /// 2. Execute the pre-hook
    /// 3. If pre-hook returns `Continue`, execute the original method via callback
    /// 4. Execute the post-hook on the result
    /// 5. Return the final outcome
    ///
    /// # Arguments
    ///
    /// * `context` - The hook context containing method call information
    /// * `thread` - The emulation thread
    /// * `execute_original` - Callback to execute the original method. Only called
    ///   if a hook matches and returns `Continue`.
    ///
    /// # Returns
    ///
    /// * `Ok(HookOutcome::NoMatch)` - No hook matched; caller should execute normally
    /// * `Ok(HookOutcome::Handled(value))` - Hook handled the call; use this result
    /// * `Err(...)` - Hook execution failed
    ///
    /// # Errors
    ///
    /// Returns an error if a pre-hook or post-hook returns `Error`.
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::emulation::{EmValue, HookContext, HookManager, HookOutcome};
    /// use dotscope::metadata::{token::Token, typesystem::PointerSize};
    /// # use std::sync::{Arc, RwLock};
    /// # use dotscope::emulation::{
    /// #     AddressSpace, CaptureContext, EmulationConfig, EmulationThread, RuntimeState,
    /// #     SharedFakeObjects, ThreadContext, ThreadId, VirtualFs,
    /// # };
    /// # let address_space = Arc::new(AddressSpace::new());
    /// # let fake_objects = SharedFakeObjects::new(address_space.managed_heap());
    /// # let context = Arc::new(ThreadContext::new(
    /// #     address_space,
    /// #     Arc::new(RwLock::new(RuntimeState::new())),
    /// #     Arc::new(CaptureContext::new()),
    /// #     Arc::new(EmulationConfig::default()),
    /// #     None,
    /// #     fake_objects,
    /// #     Arc::new(VirtualFs::new()),
    /// # ));
    /// # let mut thread = EmulationThread::new(ThreadId::MAIN, context);
    ///
    /// let manager = HookManager::new();
    /// let context = HookContext::new(
    ///     Token::new(0x0A00_0001),
    ///     "System", "String", "Concat",
    ///     PointerSize::Bit64,
    /// );
    ///
    /// let outcome = manager.execute(&context, &mut thread, |_thread| {
    ///     // Execute the original method
    ///     Some(EmValue::Null)
    /// })?;
    ///
    /// match outcome {
    ///     HookOutcome::NoMatch => { /* execute normally */ }
    ///     HookOutcome::Handled(value) => { /* use value */ }
    ///     HookOutcome::ReflectionInvoke { .. } => { /* redirect to the invoked method */ }
    ///     HookOutcome::ThrewException { .. } => { /* raise the CLR exception */ }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn execute<F>(
        &self,
        context: &HookContext<'_>,
        thread: &mut EmulationThread,
        execute_original: F,
    ) -> Result<HookOutcome>
    where
        F: FnOnce(&mut EmulationThread) -> Option<EmValue>,
    {
        // Find a matching hook. This returns an owned Arc<Hook>, so no guards
        // are held during hook execution.
        let Some(hook) = self.find_matching(context, thread)? else {
            return Ok(HookOutcome::NoMatch);
        };

        let pre_result = hook.execute_pre(context, thread);

        match pre_result {
            Some(PreHookResult::Bypass(value)) => {
                return Ok(HookOutcome::Handled(value));
            }
            Some(PreHookResult::ReflectionInvoke {
                request,
                bypass_value,
            }) => {
                return Ok(HookOutcome::ReflectionInvoke {
                    request,
                    bypass_value,
                });
            }
            Some(PreHookResult::Error(msg)) => {
                return Err(EmulationError::HookError(format!(
                    "Hook '{}' pre-hook error: {}",
                    hook.name(),
                    msg
                ))
                .into());
            }
            Some(PreHookResult::Throw {
                exception_type,
                message,
            }) => {
                return Ok(HookOutcome::ThrewException {
                    exception_type,
                    message,
                });
            }
            Some(PreHookResult::Continue) | None => {
                // Continue to original method execution
            }
        }

        let original_result = execute_original(thread);

        match hook.execute_post(context, thread, original_result.as_ref()) {
            Some(PostHookResult::Replace(new_value)) => Ok(HookOutcome::Handled(new_value)),
            Some(PostHookResult::Error(msg)) => Err(EmulationError::HookError(format!(
                "Hook '{}' post-hook error: {}",
                hook.name(),
                msg
            ))
            .into()),
            Some(PostHookResult::Keep) => Ok(HookOutcome::Handled(original_result)),
            None => {
                if original_result.is_none() {
                    Ok(HookOutcome::NoMatch)
                } else {
                    Ok(HookOutcome::Handled(original_result))
                }
            }
        }
    }

    /// Returns the number of registered hooks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.total_count.load(Ordering::Relaxed)
    }

    /// Returns `true` if no hooks are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Finds the first matching hook across all four index tiers.
    ///
    /// The search proceeds in specificity order:
    ///
    /// 1. **Full index** (namespace + type + method) — O(1) DashMap lookup.
    ///    For hooks with a single name-only matcher, the index hit is a guaranteed
    ///    match, skipping redundant `Hook::matches()` evaluation.
    /// 2. **Type index** (namespace + type) — O(1) DashMap lookup.
    /// 3. **Method index** (method name only) — O(1) DashMap lookup.
    /// 4. **Wildcard hooks** — linear scan (typically empty).
    ///
    /// Within each bucket, hooks are checked in descending priority order. The first
    /// hook whose matchers all pass is selected.
    ///
    /// Returns an owned `Arc<Hook>` so all index guards are released before hook
    /// execution begins. The Arc clone cost is negligible (~1ns atomic increment).
    ///
    /// # Errors
    ///
    /// Returns an error if the internal wildcard lock is poisoned.
    fn find_matching(
        &self,
        context: &HookContext<'_>,
        thread: &EmulationThread,
    ) -> Result<Option<Arc<Hook>>> {
        // Tier 1a: Exact name match (most common path, zero-alloc via DashMap)
        if let Some(type_map) = self.full_index.get(context.namespace) {
            if let Some(method_map) = type_map.get(context.type_name) {
                if let Some(candidates) = method_map.get(context.method_name) {
                    // Fast path: single name-only matcher → guaranteed match (already indexed)
                    for entry in candidates {
                        if !entry.has_runtime_matchers
                            && !entry.has_signature_matchers
                            && entry.hook.matchers().len() == 1
                        {
                            return Ok(Some(Arc::clone(&entry.hook)));
                        }
                        if entry.hook.matches(context, thread) {
                            return Ok(Some(Arc::clone(&entry.hook)));
                        }
                    }
                }
            }
        }

        // Tier 1b: Type-level match
        if let Some(type_map) = self.type_index.get(context.namespace) {
            if let Some(candidates) = type_map.get(context.type_name) {
                for entry in candidates {
                    if entry.hook.matches(context, thread) {
                        return Ok(Some(Arc::clone(&entry.hook)));
                    }
                }
            }
        }

        // Tier 1c: Method-only match
        if let Some(candidates) = self.method_index.get(context.method_name) {
            for entry in candidates.iter() {
                if entry.hook.matches(context, thread) {
                    return Ok(Some(Arc::clone(&entry.hook)));
                }
            }
        }

        // Tier 2: Wildcard hooks (linear scan, typically empty)
        let wildcards = self
            .wildcard_hooks
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "hook manager",
            })?;
        Ok(wildcards
            .iter()
            .find(|e| e.hook.matches(context, thread))
            .map(|e| Arc::clone(&e.hook)))
    }
}

impl std::fmt::Debug for HookManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let wildcard_count = self
            .wildcard_hooks
            .read()
            .map_err(|_| std::fmt::Error)?
            .len();
        f.debug_struct("HookManager")
            .field("hook_count", &self.total_count.load(Ordering::Relaxed))
            .field("full_index_namespaces", &self.full_index.len())
            .field("type_index_namespaces", &self.type_index.len())
            .field("method_index_entries", &self.method_index.len())
            .field("wildcard_hooks", &wildcard_count)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        emulation::HookPriority,
        metadata::{token::Token, typesystem::PointerSize},
        testkit::emulation::create_test_thread,
    };

    #[test]
    fn test_hook_manager_empty() {
        let manager = HookManager::new();
        assert!(manager.is_empty());
        assert_eq!(manager.len(), 0);
    }

    #[test]
    fn test_hook_manager_registration() {
        let manager = HookManager::new();

        manager
            .register(Hook::new("hook1").match_method_name("Method1"))
            .unwrap();
        manager
            .register(Hook::new("hook2").match_method_name("Method2"))
            .unwrap();

        assert_eq!(manager.len(), 2);
        assert!(!manager.is_empty());
    }

    #[test]
    fn test_hook_manager_priority_sorting() {
        let manager = HookManager::new();
        let mut thread = create_test_thread();

        manager
            .register(
                Hook::new("low")
                    .with_priority(HookPriority::LOW)
                    .match_method_name("Test")
                    .pre(|_ctx, _thread| PreHookResult::Bypass(Some(EmValue::I32(1)))),
            )
            .unwrap();
        manager
            .register(
                Hook::new("high")
                    .with_priority(HookPriority::HIGH)
                    .match_method_name("Test")
                    .pre(|_ctx, _thread| PreHookResult::Bypass(Some(EmValue::I32(3)))),
            )
            .unwrap();
        manager
            .register(
                Hook::new("normal")
                    .with_priority(HookPriority::NORMAL)
                    .match_method_name("Test")
                    .pre(|_ctx, _thread| PreHookResult::Bypass(Some(EmValue::I32(2)))),
            )
            .unwrap();

        // High priority should win — verified through execute
        let context = HookContext::new(
            Token::new(0x06000001),
            "System",
            "String",
            "Test",
            PointerSize::Bit64,
        );
        let outcome = manager.execute(&context, &mut thread, |_| None).unwrap();
        assert!(matches!(
            outcome,
            HookOutcome::Handled(Some(EmValue::I32(3)))
        ));
    }

    #[test]
    fn test_has_potential_match() {
        let manager = HookManager::new();

        manager
            .register(Hook::new("string-concat").match_name("System", "String", "Concat"))
            .unwrap();

        assert!(manager
            .has_potential_match("System", "String", "Concat")
            .unwrap());
        assert!(!manager
            .has_potential_match("System", "String", "Replace")
            .unwrap());
        assert!(!manager
            .has_potential_match("System", "Math", "Abs")
            .unwrap());
    }

    #[test]
    fn test_has_potential_match_with_wildcard() {
        let manager = HookManager::new();

        manager
            .register(Hook::new("wildcard").match_runtime("always", |_, _| true))
            .unwrap();

        assert!(manager
            .has_potential_match("Any", "Thing", "AtAll")
            .unwrap());
    }

    #[test]
    fn test_has_potential_match_type_level() {
        let manager = HookManager::new();

        manager
            .register(Hook::new("type-hook").match_type_name("Console"))
            .unwrap();

        // match_type_name has no namespace, goes to wildcard
        assert!(manager
            .has_potential_match("System", "Console", "WriteLine")
            .unwrap());
    }

    #[test]
    fn test_index_full_key_match() {
        let manager = HookManager::new();
        let mut thread = create_test_thread();

        manager
            .register(
                Hook::new("exact-match")
                    .match_name("System", "String", "Concat")
                    .pre(|_ctx, _thread| PreHookResult::Bypass(Some(EmValue::I32(42)))),
            )
            .unwrap();

        let context = HookContext::new(
            Token::new(0x06000001),
            "System",
            "String",
            "Concat",
            PointerSize::Bit64,
        );

        let outcome = manager
            .execute(&context, &mut thread, |_| Some(EmValue::I32(100)))
            .unwrap();

        assert!(matches!(
            outcome,
            HookOutcome::Handled(Some(EmValue::I32(42)))
        ));
    }

    #[test]
    fn test_index_method_only_match() {
        let manager = HookManager::new();
        let mut thread = create_test_thread();

        manager
            .register(
                Hook::new("method-only")
                    .match_method_name("Decrypt")
                    .pre(|_ctx, _thread| PreHookResult::Bypass(Some(EmValue::I32(99)))),
            )
            .unwrap();

        let context = HookContext::new(
            Token::new(0x06000001),
            "Custom",
            "Obfuscator",
            "Decrypt",
            PointerSize::Bit64,
        );

        let outcome = manager.execute(&context, &mut thread, |_| None).unwrap();

        assert!(matches!(
            outcome,
            HookOutcome::Handled(Some(EmValue::I32(99)))
        ));
    }

    #[test]
    fn test_execute_no_match() {
        let manager = HookManager::new();
        let mut thread = create_test_thread();
        let context = HookContext::new(
            Token::new(0x06000001),
            "System",
            "String",
            "Concat",
            PointerSize::Bit64,
        );

        let outcome = manager
            .execute(&context, &mut thread, |_| Some(EmValue::I32(100)))
            .unwrap();

        assert!(matches!(outcome, HookOutcome::NoMatch));
    }

    #[test]
    fn test_execute_pre_hook_bypass() {
        let manager = HookManager::new();
        let mut thread = create_test_thread();

        manager
            .register(
                Hook::new("bypass-test")
                    .match_name("System", "String", "Test")
                    .pre(|_ctx, _thread| PreHookResult::Bypass(Some(EmValue::I32(42)))),
            )
            .unwrap();

        let context = HookContext::new(
            Token::new(0x06000001),
            "System",
            "String",
            "Test",
            PointerSize::Bit64,
        );
        let original_called = std::sync::atomic::AtomicBool::new(false);

        let outcome = manager
            .execute(&context, &mut thread, |_| {
                original_called.store(true, std::sync::atomic::Ordering::SeqCst);
                Some(EmValue::I32(999))
            })
            .unwrap();

        assert!(matches!(
            outcome,
            HookOutcome::Handled(Some(EmValue::I32(42)))
        ));
        assert!(!original_called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn test_execute_pre_hook_continue_then_post_hook() {
        let manager = HookManager::new();
        let mut thread = create_test_thread();

        manager
            .register(
                Hook::new("continue-then-modify")
                    .match_name("System", "String", "Test")
                    .pre(|_ctx, _thread| PreHookResult::Continue)
                    .post(|_ctx, _thread, result| {
                        if let Some(EmValue::I32(v)) = result {
                            PostHookResult::Replace(Some(EmValue::I32(v * 2)))
                        } else {
                            PostHookResult::Keep
                        }
                    }),
            )
            .unwrap();

        let context = HookContext::new(
            Token::new(0x06000001),
            "System",
            "String",
            "Test",
            PointerSize::Bit64,
        );
        let outcome = manager
            .execute(&context, &mut thread, |_| Some(EmValue::I32(50)))
            .unwrap();

        assert!(matches!(
            outcome,
            HookOutcome::Handled(Some(EmValue::I32(100)))
        ));
    }

    #[test]
    fn test_execute_pre_hook_error() {
        let manager = HookManager::new();
        let mut thread = create_test_thread();

        manager
            .register(
                Hook::new("error-test")
                    .match_name("System", "String", "Test")
                    .pre(|_ctx, _thread| PreHookResult::Error("test error".to_string())),
            )
            .unwrap();

        let context = HookContext::new(
            Token::new(0x06000001),
            "System",
            "String",
            "Test",
            PointerSize::Bit64,
        );
        let result = manager.execute(&context, &mut thread, |_| Some(EmValue::I32(100)));

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("test error"));
    }

    #[test]
    fn test_execute_post_hook_keep() {
        let manager = HookManager::new();
        let mut thread = create_test_thread();

        manager
            .register(
                Hook::new("post-keep")
                    .match_name("System", "String", "Test")
                    .pre(|_ctx, _thread| PreHookResult::Continue)
                    .post(|_ctx, _thread, _result| PostHookResult::Keep),
            )
            .unwrap();

        let context = HookContext::new(
            Token::new(0x06000001),
            "System",
            "String",
            "Test",
            PointerSize::Bit64,
        );
        let outcome = manager
            .execute(&context, &mut thread, |_| Some(EmValue::I32(123)))
            .unwrap();

        assert!(matches!(
            outcome,
            HookOutcome::Handled(Some(EmValue::I32(123)))
        ));
    }

    #[test]
    fn test_execute_post_hook_error() {
        let manager = HookManager::new();
        let mut thread = create_test_thread();

        manager
            .register(
                Hook::new("post-error")
                    .match_name("System", "String", "Test")
                    .pre(|_ctx, _thread| PreHookResult::Continue)
                    .post(|_ctx, _thread, _result| PostHookResult::Error("post error".to_string())),
            )
            .unwrap();

        let context = HookContext::new(
            Token::new(0x06000001),
            "System",
            "String",
            "Test",
            PointerSize::Bit64,
        );
        let result = manager.execute(&context, &mut thread, |_| Some(EmValue::I32(100)));

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("post error"));
    }

    #[test]
    fn test_multiple_hooks_same_key_priority_order() {
        let manager = HookManager::new();
        let mut thread = create_test_thread();

        manager
            .register(
                Hook::new("low-priority")
                    .with_priority(HookPriority::LOW)
                    .match_name("System", "String", "Concat")
                    .pre(|_ctx, _thread| PreHookResult::Bypass(Some(EmValue::I32(1)))),
            )
            .unwrap();
        manager
            .register(
                Hook::new("high-priority")
                    .with_priority(HookPriority::HIGH)
                    .match_name("System", "String", "Concat")
                    .pre(|_ctx, _thread| PreHookResult::Bypass(Some(EmValue::I32(2)))),
            )
            .unwrap();

        let context = HookContext::new(
            Token::new(0x06000001),
            "System",
            "String",
            "Concat",
            PointerSize::Bit64,
        );

        let outcome = manager.execute(&context, &mut thread, |_| None).unwrap();

        assert!(matches!(
            outcome,
            HookOutcome::Handled(Some(EmValue::I32(2)))
        ));
    }

    #[test]
    fn test_registration_count() {
        let manager = HookManager::new();

        manager
            .register(Hook::new("hook1").match_name("System", "String", "Concat"))
            .unwrap();
        manager
            .register(Hook::new("hook2").match_name("System", "Math", "Abs"))
            .unwrap();
        manager
            .register(Hook::new("hook3").match_method_name("Decrypt"))
            .unwrap();

        assert_eq!(manager.len(), 3);
    }
}

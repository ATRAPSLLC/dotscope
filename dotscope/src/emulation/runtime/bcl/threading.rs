//! `System.Threading` method hooks.
//!
//! Provides implementations for threading primitives used in obfuscated code.
//! Since emulation is single-threaded, locks always succeed and `Interlocked`
//! operations are simple read-modify-write sequences.
//!
//! # Emulated Methods
//!
//! ## Monitor
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Monitor.Enter(object)` | Acquires lock, increments re-entrant count |
//! | `Monitor.Enter(object, ref bool)` | Acquires lock, sets lockTaken = true |
//! | `Monitor.Exit(object)` | Releases lock, decrements re-entrant count |
//! | `Monitor.TryEnter(...)` | Acquires lock (always succeeds in single-threaded) |
//! | `Monitor.Wait(...)` | Release + re-acquire lock, return true (single-threaded) |
//! | `Monitor.Pulse(object)` | No-op (no threads to wake) |
//! | `Monitor.PulseAll(object)` | No-op (no threads to wake) |
//!
//! ## Interlocked
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Interlocked.CompareExchange(ref, value, comparand)` | Atomic CAS |
//! | `Interlocked.Exchange(ref, value)` | Atomic swap |
//! | `Interlocked.Increment(ref int)` | Atomic increment |
//! | `Interlocked.Decrement(ref int)` | Atomic decrement |
//! | `Interlocked.Add(ref int, value)` | Atomic add |
//!
//! ## Thread
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Thread.Sleep(int)` | No-op (skip delay in emulation) |
//! | `Thread.get_CurrentThread` | Returns stub thread object |
//! | `Thread.get_ManagedThreadId` | Returns 1 (single-threaded) |
//!

use log::debug;

use crate::{
    emulation::{
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        tokens,
        value::PointerTarget,
        EmValue, ManagedPointer,
    },
    Result,
};

/// Registers all threading method hooks with the given hook manager.
pub fn register(manager: &HookManager) -> Result<()> {
    // Monitor methods
    manager.register(
        Hook::new("System.Threading.Monitor.Enter")
            .match_name("System.Threading", "Monitor", "Enter")
            .pre(monitor_enter_pre),
    )?;

    manager.register(
        Hook::new("System.Threading.Monitor.Exit")
            .match_name("System.Threading", "Monitor", "Exit")
            .pre(monitor_exit_pre),
    )?;

    manager.register(
        Hook::new("System.Threading.Monitor.TryEnter")
            .match_name("System.Threading", "Monitor", "TryEnter")
            .pre(monitor_try_enter_pre),
    )?;

    manager.register(
        Hook::new("System.Threading.Monitor.Wait")
            .match_name("System.Threading", "Monitor", "Wait")
            .pre(monitor_wait_pre),
    )?;

    manager.register(
        Hook::new("System.Threading.Monitor.Pulse")
            .match_name("System.Threading", "Monitor", "Pulse")
            .pre(monitor_pulse_pre),
    )?;

    manager.register(
        Hook::new("System.Threading.Monitor.PulseAll")
            .match_name("System.Threading", "Monitor", "PulseAll")
            .pre(monitor_pulse_pre),
    )?;

    // Interlocked methods
    manager.register(
        Hook::new("System.Threading.Interlocked.CompareExchange")
            .match_name("System.Threading", "Interlocked", "CompareExchange")
            .pre(interlocked_compare_exchange_pre),
    )?;

    manager.register(
        Hook::new("System.Threading.Interlocked.Exchange")
            .match_name("System.Threading", "Interlocked", "Exchange")
            .pre(interlocked_exchange_pre),
    )?;

    manager.register(
        Hook::new("System.Threading.Interlocked.Increment")
            .match_name("System.Threading", "Interlocked", "Increment")
            .pre(interlocked_increment_pre),
    )?;

    manager.register(
        Hook::new("System.Threading.Interlocked.Decrement")
            .match_name("System.Threading", "Interlocked", "Decrement")
            .pre(interlocked_decrement_pre),
    )?;

    manager.register(
        Hook::new("System.Threading.Interlocked.Add")
            .match_name("System.Threading", "Interlocked", "Add")
            .pre(interlocked_add_pre),
    )?;

    // Thread methods
    manager.register(
        Hook::new("System.Threading.Thread.Sleep")
            .match_name("System.Threading", "Thread", "Sleep")
            .pre(thread_sleep_pre),
    )?;

    manager.register(
        Hook::new("System.Threading.Thread.get_CurrentThread")
            .match_name("System.Threading", "Thread", "get_CurrentThread")
            .pre(thread_get_current_thread_pre),
    )?;

    manager.register(
        Hook::new("System.Threading.Thread.get_ManagedThreadId")
            .match_name("System.Threading", "Thread", "get_ManagedThreadId")
            .pre(thread_get_managed_thread_id_pre),
    )?;

    Ok(())
}

/// Extracts the heap object ID from the lock object argument.
///
/// The first argument to all Monitor methods is the lock object. Returns
/// `Some(id)` for valid object references, `None` otherwise.
fn extract_lock_object_id(ctx: &HookContext<'_>) -> Option<u64> {
    ctx.args.first().and_then(|arg| match arg {
        EmValue::ObjectRef(href) => Some(href.id()),
        _ => None,
    })
}

/// Sets the `ref bool lockTaken` out parameter to `true`.
///
/// Scans the arguments for a `ManagedPtr` (the `ref bool` parameter) and
/// writes `I32(1)` through it. Called by both `Enter` and `TryEnter` overloads.
fn set_lock_taken(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> Result<()> {
    // The ref bool is always the last argument in Monitor overloads that have it
    if let Some(EmValue::ManagedPtr(ptr)) = ctx.args.last() {
        // Only treat it as lockTaken if there are at least 2 args (object + ref bool)
        if ctx.args.len() >= 2 {
            thread.store_through_pointer(ptr, EmValue::I32(1))?;
        }
    }
    Ok(())
}

/// Hook for `Monitor.Enter(object)` and `Monitor.Enter(object, ref bool)`.
///
/// Acquires the monitor lock on the object and increments the re-entrant count.
/// For the 2-arg overload, writes `true` to the `ref bool lockTaken` parameter.
fn monitor_enter_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(obj_id) = extract_lock_object_id(ctx) {
        thread.address_space().monitor_enter(obj_id);
    }
    // Set lockTaken = true for the (object, ref bool) overload
    try_hook!(set_lock_taken(ctx, thread));
    PreHookResult::Bypass(None)
}

/// Hook for `Monitor.Exit(object)`.
///
/// Releases the monitor lock, decrementing the re-entrant count. Logs a
/// warning if Exit is called without a matching Enter (this would throw
/// `SynchronizationLockException` in a real runtime).
fn monitor_exit_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(obj_id) = extract_lock_object_id(ctx) {
        if !thread.address_space().monitor_exit(obj_id) {
            debug!(
                "Monitor.Exit: object {} was not locked (mismatched Enter/Exit)",
                obj_id
            );
        }
    }
    PreHookResult::Bypass(None)
}

/// Hook for `Monitor.TryEnter(...)` overloads.
///
/// All overloads acquire the lock (always succeeds in single-threaded emulation)
/// and return `true`. For overloads with `ref bool lockTaken`, writes `true`.
///
/// Overloads:
/// - `TryEnter(object) -> bool`
/// - `TryEnter(object, int) -> bool`
/// - `TryEnter(object, TimeSpan) -> bool`
/// - `TryEnter(object, ref bool)` (void, sets lockTaken)
/// - `TryEnter(object, int, ref bool)` (void, sets lockTaken)
/// - `TryEnter(object, TimeSpan, ref bool)` (void, sets lockTaken)
fn monitor_try_enter_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(obj_id) = extract_lock_object_id(ctx) {
        thread.address_space().monitor_enter(obj_id);
    }
    // Set lockTaken for overloads that have ref bool
    try_hook!(set_lock_taken(ctx, thread));
    // Return true for overloads that return bool; void overloads ignore the value
    PreHookResult::Bypass(Some(EmValue::I32(1)))
}

/// Hook for `Monitor.Wait(...)` overloads.
///
/// In single-threaded emulation there are no other threads to signal, so Wait
/// releases the lock and immediately re-acquires it, simulating an instant
/// signal. Returns `true` (signaled).
///
/// Overloads:
/// - `Wait(object) -> bool`
/// - `Wait(object, int) -> bool`
/// - `Wait(object, TimeSpan) -> bool`
/// - `Wait(object, int, bool) -> bool`
fn monitor_wait_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(obj_id) = extract_lock_object_id(ctx) {
        // Release and immediately re-acquire to simulate instant signal
        thread.address_space().monitor_exit(obj_id);
        thread.address_space().monitor_enter(obj_id);
    }
    // All overloads return bool — true means "signaled before timeout"
    PreHookResult::Bypass(Some(EmValue::I32(1)))
}

/// Hook for `Monitor.Pulse(object)` and `Monitor.PulseAll(object)`.
///
/// No-op in single-threaded emulation — there are no waiting threads to wake.
fn monitor_pulse_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(None)
}

/// Reads the current value through a `ManagedPtr` argument.
fn read_through_ptr(thread: &EmulationThread, ptr: &ManagedPointer) -> EmValue {
    match &ptr.target {
        PointerTarget::Local(idx) => thread
            .get_frame_at(ptr.frame_depth)
            .or_else(|| thread.current_frame())
            .and_then(|f| f.locals().get(usize::from(*idx)).ok().cloned())
            .unwrap_or(EmValue::Null),
        PointerTarget::Argument(idx) => thread
            .get_frame_at(ptr.frame_depth)
            .or_else(|| thread.current_frame())
            .and_then(|f| f.arguments().get(usize::from(*idx)).ok().cloned())
            .unwrap_or(EmValue::Null),
        PointerTarget::StaticField(field) => thread
            .address_space()
            .get_static(*field)
            .ok()
            .flatten()
            .unwrap_or(EmValue::Null),
        PointerTarget::ObjectField { object, field } => thread
            .heap()
            .get_field(*object, *field)
            .ok()
            .unwrap_or(EmValue::Null),
        PointerTarget::ArrayElement { array, index } => thread
            .heap()
            .get_array_element(*array, *index)
            .ok()
            .unwrap_or(EmValue::Null),
    }
}

/// Hook for `Interlocked.CompareExchange(ref location, value, comparand)`.
///
/// Atomically compares `location` with `comparand`. If equal, replaces `location`
/// with `value`. Returns the original value of `location`.
fn interlocked_compare_exchange_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // args: [ref location, value, comparand]
    let (ptr, value, comparand) = match (ctx.args.first(), ctx.args.get(1), ctx.args.get(2)) {
        (Some(EmValue::ManagedPtr(p)), Some(v), Some(c)) => (p, v, c),
        _ => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    let current = read_through_ptr(thread, ptr);
    if current == *comparand {
        try_hook!(thread.store_through_pointer(ptr, value.clone()));
    }
    PreHookResult::Bypass(Some(current))
}

/// Hook for `Interlocked.Exchange(ref location, value)`.
///
/// Atomically sets `location` to `value` and returns the original value.
fn interlocked_exchange_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let (ptr, value) = match (ctx.args.first(), ctx.args.get(1)) {
        (Some(EmValue::ManagedPtr(p)), Some(v)) => (p, v),
        _ => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    let current = read_through_ptr(thread, ptr);
    try_hook!(thread.store_through_pointer(ptr, value.clone()));
    PreHookResult::Bypass(Some(current))
}

/// Hook for `Interlocked.Increment(ref int)`.
///
/// Atomically increments the value and returns the incremented value.
fn interlocked_increment_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let ptr = match ctx.args.first() {
        Some(EmValue::ManagedPtr(p)) => p,
        _ => return PreHookResult::Bypass(Some(EmValue::I32(1))),
    };

    let current = read_through_ptr(thread, ptr);
    let result = match current {
        EmValue::I32(v) => EmValue::I32(v.wrapping_add(1)),
        EmValue::I64(v) => EmValue::I64(v.wrapping_add(1)),
        _ => EmValue::I32(1),
    };
    try_hook!(thread.store_through_pointer(ptr, result.clone()));
    PreHookResult::Bypass(Some(result))
}

/// Hook for `Interlocked.Decrement(ref int)`.
///
/// Atomically decrements the value and returns the decremented value.
fn interlocked_decrement_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let ptr = match ctx.args.first() {
        Some(EmValue::ManagedPtr(p)) => p,
        _ => return PreHookResult::Bypass(Some(EmValue::I32(-1))),
    };

    let current = read_through_ptr(thread, ptr);
    let result = match current {
        EmValue::I32(v) => EmValue::I32(v.wrapping_sub(1)),
        EmValue::I64(v) => EmValue::I64(v.wrapping_sub(1)),
        _ => EmValue::I32(-1),
    };
    try_hook!(thread.store_through_pointer(ptr, result.clone()));
    PreHookResult::Bypass(Some(result))
}

/// Hook for `Interlocked.Add(ref int, value)`.
///
/// Atomically adds `value` to the location and returns the new value.
fn interlocked_add_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let (ptr, addend) = match (ctx.args.first(), ctx.args.get(1)) {
        (Some(EmValue::ManagedPtr(p)), Some(v)) => (p, v),
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    let current = read_through_ptr(thread, ptr);
    let result = match (&current, addend) {
        (EmValue::I32(a), EmValue::I32(b)) => EmValue::I32(a.wrapping_add(*b)),
        (EmValue::I64(a), EmValue::I64(b)) => EmValue::I64(a.wrapping_add(*b)),
        _ => addend.clone(),
    };
    try_hook!(thread.store_through_pointer(ptr, result.clone()));
    PreHookResult::Bypass(Some(result))
}

/// Hook for `Thread.Sleep(int)` / `Thread.Sleep(TimeSpan)`.
///
/// No-op in emulation — skip the delay.
fn thread_sleep_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(None)
}

/// Hook for `Thread.get_CurrentThread`.
///
/// Returns a stub Thread object.
fn thread_get_current_thread_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    match thread.heap_mut().alloc_object(tokens::system::THREAD) {
        Ok(obj_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(obj_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `Thread.get_ManagedThreadId`.
///
/// Returns 1 (single-threaded emulation).
fn thread_get_managed_thread_id_pre(
    _ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    PreHookResult::Bypass(Some(EmValue::I32(1)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        emulation::runtime::hook::HookManager,
        metadata::{token::Token, typesystem::PointerSize},
        testkit::emulation::create_test_thread,
    };

    fn ctx<'a>(
        type_name: &'a str,
        method: &'a str,
        this: Option<&'a EmValue>,
        args: &'a [EmValue],
    ) -> HookContext<'a> {
        HookContext::new(
            Token::new(0x0A000001),
            "System.Threading",
            type_name,
            method,
            PointerSize::Bit64,
        )
        .with_this(this)
        .with_args(args)
    }

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        register(&manager).unwrap();
        assert_eq!(manager.len(), 14);
    }

    #[test]
    fn test_monitor_enter() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let args = [EmValue::ObjectRef(obj)];
        let result = monitor_enter_pre(&ctx("Monitor", "Enter", None, &args), &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(None)));
    }

    #[test]
    fn test_monitor_exit() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        // Enter first, then exit
        let args = [EmValue::ObjectRef(obj)];
        monitor_enter_pre(&ctx("Monitor", "Enter", None, &args), &mut thread);
        let result = monitor_exit_pre(&ctx("Monitor", "Exit", None, &args), &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(None)));
    }

    #[test]
    fn test_monitor_try_enter() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let args = [EmValue::ObjectRef(obj)];
        let result = monitor_try_enter_pre(&ctx("Monitor", "TryEnter", None, &args), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));
    }

    #[test]
    fn test_monitor_wait() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let args = [EmValue::ObjectRef(obj)];
        monitor_enter_pre(&ctx("Monitor", "Enter", None, &args), &mut thread);
        let result = monitor_wait_pre(&ctx("Monitor", "Wait", None, &args), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));
    }

    #[test]
    fn test_monitor_pulse() {
        let mut thread = create_test_thread();
        let result = monitor_pulse_pre(&ctx("Monitor", "Pulse", None, &[]), &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(None)));
    }

    #[test]
    fn test_thread_sleep() {
        let mut thread = create_test_thread();
        let args = [EmValue::I32(1000)];
        let result = thread_sleep_pre(&ctx("Thread", "Sleep", None, &args), &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(None)));
    }

    #[test]
    fn test_thread_get_current_thread() {
        let mut thread = create_test_thread();
        let result = thread_get_current_thread_pre(
            &ctx("Thread", "get_CurrentThread", None, &[]),
            &mut thread,
        );
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_)))
        ));
    }

    #[test]
    fn test_thread_get_managed_thread_id() {
        let mut thread = create_test_thread();
        let result = thread_get_managed_thread_id_pre(
            &ctx("Thread", "get_ManagedThreadId", None, &[]),
            &mut thread,
        );
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));
    }

    #[test]
    fn test_interlocked_increment_no_pointer() {
        let mut thread = create_test_thread();
        let result =
            interlocked_increment_pre(&ctx("Interlocked", "Increment", None, &[]), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));
    }

    #[test]
    fn test_interlocked_decrement_no_pointer() {
        let mut thread = create_test_thread();
        let result =
            interlocked_decrement_pre(&ctx("Interlocked", "Decrement", None, &[]), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(-1)))
        ));
    }

    #[test]
    fn test_interlocked_exchange_no_pointer() {
        let mut thread = create_test_thread();
        let result =
            interlocked_exchange_pre(&ctx("Interlocked", "Exchange", None, &[]), &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(Some(EmValue::Null))));
    }

    #[test]
    fn test_interlocked_compare_exchange_no_pointer() {
        let mut thread = create_test_thread();
        let result = interlocked_compare_exchange_pre(
            &ctx("Interlocked", "CompareExchange", None, &[]),
            &mut thread,
        );
        assert!(matches!(result, PreHookResult::Bypass(Some(EmValue::Null))));
    }

    #[test]
    fn test_interlocked_add_no_pointer() {
        let mut thread = create_test_thread();
        let result = interlocked_add_pre(&ctx("Interlocked", "Add", None, &[]), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0)))
        ));
    }

    #[test]
    fn test_interlocked_increment_via_static() {
        let mut thread = create_test_thread();
        let field_token = Token::new(0x04000001);
        thread
            .address_space()
            .set_static(field_token, EmValue::I32(10))
            .unwrap();

        let ptr = ManagedPointer {
            target: PointerTarget::StaticField(field_token),
            offset: 0,
            frame_depth: 0,
        };
        let args = [EmValue::ManagedPtr(ptr)];
        let result =
            interlocked_increment_pre(&ctx("Interlocked", "Increment", None, &args), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(11)))
        ));
    }

    #[test]
    fn test_interlocked_decrement_via_static() {
        let mut thread = create_test_thread();
        let field_token = Token::new(0x04000001);
        thread
            .address_space()
            .set_static(field_token, EmValue::I32(10))
            .unwrap();

        let ptr = ManagedPointer {
            target: PointerTarget::StaticField(field_token),
            offset: 0,
            frame_depth: 0,
        };
        let args = [EmValue::ManagedPtr(ptr)];
        let result =
            interlocked_decrement_pre(&ctx("Interlocked", "Decrement", None, &args), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(9)))
        ));
    }

    #[test]
    fn test_interlocked_exchange_via_static() {
        let mut thread = create_test_thread();
        let field_token = Token::new(0x04000001);
        thread
            .address_space()
            .set_static(field_token, EmValue::I32(5))
            .unwrap();

        let ptr = ManagedPointer {
            target: PointerTarget::StaticField(field_token),
            offset: 0,
            frame_depth: 0,
        };
        let args = [EmValue::ManagedPtr(ptr), EmValue::I32(99)];
        let result =
            interlocked_exchange_pre(&ctx("Interlocked", "Exchange", None, &args), &mut thread);
        // Returns old value
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(5)))
        ));
        // New value stored
        assert_eq!(
            thread.address_space().get_static(field_token).unwrap(),
            Some(EmValue::I32(99))
        );
    }

    #[test]
    fn test_interlocked_compare_exchange_matching() {
        let mut thread = create_test_thread();
        let field_token = Token::new(0x04000001);
        thread
            .address_space()
            .set_static(field_token, EmValue::I32(10))
            .unwrap();

        let ptr = ManagedPointer {
            target: PointerTarget::StaticField(field_token),
            offset: 0,
            frame_depth: 0,
        };
        // args: [ref location, value, comparand]
        let args = [EmValue::ManagedPtr(ptr), EmValue::I32(20), EmValue::I32(10)];
        let result = interlocked_compare_exchange_pre(
            &ctx("Interlocked", "CompareExchange", None, &args),
            &mut thread,
        );
        // Returns old value (10)
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(10)))
        ));
        // Value was swapped to 20
        assert_eq!(
            thread.address_space().get_static(field_token).unwrap(),
            Some(EmValue::I32(20))
        );
    }

    #[test]
    fn test_interlocked_compare_exchange_not_matching() {
        let mut thread = create_test_thread();
        let field_token = Token::new(0x04000001);
        thread
            .address_space()
            .set_static(field_token, EmValue::I32(10))
            .unwrap();

        let ptr = ManagedPointer {
            target: PointerTarget::StaticField(field_token),
            offset: 0,
            frame_depth: 0,
        };
        // comparand doesn't match
        let args = [EmValue::ManagedPtr(ptr), EmValue::I32(20), EmValue::I32(99)];
        let result = interlocked_compare_exchange_pre(
            &ctx("Interlocked", "CompareExchange", None, &args),
            &mut thread,
        );
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(10)))
        ));
        // Value unchanged
        assert_eq!(
            thread.address_space().get_static(field_token).unwrap(),
            Some(EmValue::I32(10))
        );
    }

    #[test]
    fn test_interlocked_increment_i64() {
        let mut thread = create_test_thread();
        let field_token = Token::new(0x04000001);
        thread
            .address_space()
            .set_static(field_token, EmValue::I64(100))
            .unwrap();

        let ptr = ManagedPointer {
            target: PointerTarget::StaticField(field_token),
            offset: 0,
            frame_depth: 0,
        };
        let args = [EmValue::ManagedPtr(ptr)];
        let result =
            interlocked_increment_pre(&ctx("Interlocked", "Increment", None, &args), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I64(101)))
        ));
    }

    #[test]
    fn test_interlocked_decrement_i64() {
        let mut thread = create_test_thread();
        let field_token = Token::new(0x04000001);
        thread
            .address_space()
            .set_static(field_token, EmValue::I64(100))
            .unwrap();

        let ptr = ManagedPointer {
            target: PointerTarget::StaticField(field_token),
            offset: 0,
            frame_depth: 0,
        };
        let args = [EmValue::ManagedPtr(ptr)];
        let result =
            interlocked_decrement_pre(&ctx("Interlocked", "Decrement", None, &args), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I64(99)))
        ));
    }
}

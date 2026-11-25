//! Memory model for CIL emulation.
//!
//! This module provides the memory structures used during CIL bytecode emulation.
//! It implements a complete memory model including stack, heap, and address space
//! management.
//!
//! # Core Types
//!
//! | Type | Description |
//! |------|-------------|
//! | [`EvaluationStack`] | The CIL operand stack for instruction operands and results |
//! | [`LocalVariables`] | Method-scoped storage for local variables |
//! | [`ArgumentStorage`] | Storage for method parameters |
//! | [`ManagedHeap`] | Simulated GC heap for objects, arrays, and strings |
//! | [`AddressSpace`] | Unified view of all memory (heap, regions, statics) |
//! | [`MemoryRegion`] | Memory region types (PE images, mapped data, allocations) |
//! | [`StaticFieldStorage`] | Storage for static (class-level) fields |
//! | [`UnmanagedMemory`] | Raw byte-level memory for `localloc`, `cpblk`, etc. |
//!
//! # CIL Memory Model
//!
//! The CIL virtual machine uses a stack-based evaluation model with several
//! distinct memory areas:
//!
//! 1. **Evaluation Stack** - Instructions pop operands and push results. Each
//!    method invocation has its own stack that starts empty.
//!
//! 2. **Local Variables** - Method-scoped storage slots defined by the method's
//!    local signature. Initialized to default values at method entry.
//!
//! 3. **Arguments** - Parameters passed to methods. For instance methods,
//!    argument 0 is the `this` reference.
//!
//! 4. **Managed Heap** - Reference types (objects, arrays, strings) are allocated
//!    here and accessed via references.
//!
//! 5. **Static Fields** - Type-level fields shared across all instances and threads.
//!
//! # Example
//!
//! ```rust
//! use dotscope::emulation::{EmValue, EvaluationStack, LocalVariables};
//! use dotscope::metadata::typesystem::CilFlavor;
//!
//! // Create an evaluation stack with overflow protection
//! let mut stack = EvaluationStack::new(1000);
//!
//! // Push values onto the stack
//! stack.push(EmValue::I32(10)).unwrap();
//! stack.push(EmValue::I32(20)).unwrap();
//!
//! // Pop and use values (stack is LIFO)
//! let b = stack.pop().unwrap(); // 20
//! let a = stack.pop().unwrap(); // 10
//!
//! // Create local variables from type information
//! let mut locals = LocalVariables::new(vec![CilFlavor::I4, CilFlavor::Object]);
//! locals.set(0, EmValue::I32(42)).unwrap();
//! ```
//!
//! # Thread Safety
//!
//! Most types in this module use interior mutability for thread-safe access:
//! - [`ManagedHeap`] uses `RwLock` for concurrent access
//! - [`AddressSpace`] uses `RwLock` for region management
//! - [`StaticFieldStorage`] uses `RwLock` for field access

mod addressspace;
mod arguments;
mod heap;
mod locals;
mod page;
mod region;
mod stack;
mod statics;
mod unmanaged;

pub use addressspace::{AddressSpace, SharedHeap};
pub use arguments::ArgumentStorage;
pub use heap::{
    DelegateEntry, DictionaryKey, EncodingType, HeapIter, HeapObject, HeapState, ManagedHeap,
    ManagedString, TypeWrapper,
};
pub use locals::LocalVariables;
pub use page::{Page, PageDataGuard, PAGE_SIZE};
pub use region::{MemoryProtection, MemoryRegion, SectionInfo, ThreadId};
pub use stack::EvaluationStack;
pub use statics::{StaticFieldStorage, TypeInitState};
pub use unmanaged::{UnmanagedMemory, UnmanagedRef};

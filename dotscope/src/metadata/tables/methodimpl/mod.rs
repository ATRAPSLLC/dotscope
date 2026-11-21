//! `MethodImpl` table implementation for method implementation mappings.
//!
//! This module provides complete support for the `MethodImpl` metadata table, which defines
//! method implementation mappings that specify which concrete method implementations provide
//! the behavior for method declarations. The `MethodImpl` table is essential for interface
//! implementation, method overriding, and virtual dispatch in .NET object-oriented programming.
//!
//! # Architecture
//!
//! The module implements a complete processing pipeline for method implementation mappings:
//!
//! - **Raw Processing**: [`crate::metadata::tables::methodimpl::raw::MethodImplRaw`] handles direct table parsing with coded index resolution
//! - **Owned Structures**: [`crate::metadata::tables::methodimpl::owned::MethodImpl`] provides resolved references and semantic relationships
//! - **Parallel Loading**: [`crate::metadata::loader::tables::MethodImplLoader`] coordinates dependency-aware processing
//! - **Collection Types**: Thread-safe containers enable concurrent access and efficient lookup operations
//!
//! # Processing Pipeline
//!
//! Method implementation processing follows a structured approach:
//!
//! 1. **Table Parsing**: Extract raw entries from metadata tables stream
//! 2. **Dependency Resolution**: Resolve `MethodDefOrRef` coded indexes to concrete methods
//! 3. **Implementation Mapping**: Link method declarations to their concrete implementations
//! 4. **Virtual Dispatch**: Build relationships for polymorphic method resolution
//! 5. **Semantic Validation**: Ensure implementation mappings satisfy interface contracts
//!
//! # Module Components
//! - [`MethodImplRaw`] - Raw table structure with unresolved coded indexes
//! - [`MethodImpl`] - Owned variant with resolved references and implementation mappings
//! - [`MethodImplLoader`](crate::metadata::loader::tables::MethodImplLoader) - Internal loader for processing table entries (crate-private)
//! - Type aliases for collections: [`MethodImplMap`], [`MethodImplList`], [`MethodImplRc`]
//!
//! # Table Structure (ECMA-335 §22.27)
//! | Column | Type | Description |
//! |--------|------|-------------|
//! | Class | `TypeDef` table index | Type containing the implementation mapping |
//! | `MethodBody` | `MethodDefOrRef` coded index | Concrete method implementation |
//! | `MethodDeclaration` | `MethodDefOrRef` coded index | Method declaration being implemented |
//!
//! # Implementation Mapping Scenarios
//!
//! The `MethodImpl` table supports sophisticated method implementation patterns essential for .NET polymorphism:
//!
//! ## Interface Implementation
//! Maps interface method declarations to concrete class implementations, enabling interface contracts:
//! ```csharp
//! interface IExample { void Method(); }
//! class Implementation : IExample {
//!     public void Method() { } // MethodImpl entry links interface method to implementation
//! }
//! ```
//!
//! ## Virtual Method Override
//! Specifies derived class methods that override base class virtual methods:
//! ```csharp
//! class Base { public virtual void Method() { } }
//! class Derived : Base {
//!     public override void Method() { } // MethodImpl entry for override relationship
//! }
//! ```
//!
//! ## Explicit Interface Implementation
//! Handles explicit implementation of interface members with name resolution:
//! ```csharp
//! class Example : IExample {
//!     void IExample.Method() { } // MethodImpl entry for explicit implementation
//! }
//! ```
//!
//! ## Generic Method Specialization
//! Links generic method declarations to specialized implementations for specific type arguments:
//! ```csharp
//! class Generic<T> {
//!     public virtual void Method<U>() { }
//! }
//! class Specialized : Generic<string> {
//!     public override void Method<int>() { } // MethodImpl for specialized generic method
//! }
//! ```
//!
//! ## Abstract Method Implementation
//! Connects abstract method declarations to concrete implementations in derived classes:
//! ```csharp
//! abstract class Base { public abstract void Method(); }
//! class Concrete : Base {
//!     public override void Method() { } // MethodImpl entry for abstract implementation
//! }
//! ```
//!
//! # Method Resolution Process
//!
//! Implementation mappings enable sophisticated method resolution that forms the foundation of .NET polymorphism:
//!
//! ## Declaration Identification
//! The runtime determines which method declaration is being implemented by analyzing:
//! - **Signature Matching**: Method signatures must be compatible between declaration and implementation
//! - **Type Hierarchy**: Implementation methods must be accessible within the inheritance chain
//! - **Generic Constraints**: Generic method implementations must satisfy type parameter constraints
//! - **Access Modifiers**: Implementation visibility must meet declaration requirements
//!
//! ## Implementation Binding
//! Links declarations to their concrete implementation methods through:
//! - **Direct Mapping**: One-to-one relationships between interface methods and implementations
//! - **Override Chains**: Multi-level inheritance with method overriding at different levels
//! - **Default Implementations**: Interface default methods with potential overrides
//! - **Explicit Mappings**: Manually specified implementation relationships via MethodImpl attributes
//!
//! ## Virtual Dispatch
//! Supports polymorphic method calls through implementation mappings:
//! - **Runtime Resolution**: Method selection based on actual object type at runtime
//! - **V-Table Construction**: Building virtual method tables for efficient dispatch
//! - **Interface Dispatch**: Resolving interface method calls to appropriate implementations
//! - **Generic Instantiation**: Method resolution for generic type and method instantiations
//!
//! ## Interface Contracts
//! Ensures interface method contracts are properly implemented:
//! - **Contract Validation**: Verifying all interface methods have implementations
//! - **Signature Compatibility**: Ensuring implementation signatures match interface declarations
//! - **Accessibility Requirements**: Confirming implementations meet interface accessibility rules
//! - **Constraint Satisfaction**: Validating generic constraint satisfaction in implementations
//!
//! ## Inheritance Hierarchies
//! Manages method overriding in complex class inheritance chains:
//! - **Override Resolution**: Determining the most derived override in inheritance chains
//! - **Hiding vs. Overriding**: Distinguishing between method hiding and true overriding
//! - **Abstract Implementation**: Resolving abstract methods to concrete implementations
//! - **Multi-Interface**: Managing implementations when a class implements multiple interfaces
//!
//! # Coded Index Resolution
//! Both `MethodBody` and `MethodDeclaration` use `MethodDefOrRef` coded index encoding:
//! - **Tag 0**: `MethodDef` table (methods defined in current assembly)
//! - **Tag 1**: `MemberRef` table (methods referenced from external assemblies)
//!
//! # Thread Safety
//!
//! All components in this module are designed for safe concurrent access:
//!
//! - **[`MethodImplMap`]**: Uses [`crossbeam_skiplist::SkipMap`] for lock-free concurrent access to implementation mappings
//! - **[`MethodImplList`]**: Employs [`boxcar::Vec`] wrapped in [`std::sync::Arc`] for thread-safe shared ownership
//! - **[`MethodImplRc`]**: Utilizes [`std::sync::Arc`] for safe sharing of implementation data across threads
//! - **Loader Operations**: All loading and processing operations are [`std::marker::Send`] + [`std::marker::Sync`] compatible
//! - **Dependency Resolution**: Concurrent coded index resolution during parallel metadata loading
//!
//! Implementation mappings can be safely accessed and queried from multiple threads without additional synchronization,
//! enabling efficient parallel processing of method resolution operations.
//!
//! # Integration
//!
//! This module integrates with several core components of the metadata system:
//!
//! - **[`crate::metadata::tables::methoddef`]**: Resolves method definition references for implementation bodies
//! - **[`crate::metadata::tables::memberref`]**: Handles external method references in implementation mappings
//! - **[`crate::metadata::tables::typedef`]**: Links implementation mappings to their containing types
//! - **[`crate::metadata::typesystem`]**: Provides type resolution and inheritance hierarchy analysis
//! - **Internal loader context**: Coordinates dependency resolution during parallel loading
//! - **[`crate::metadata::streams`]**: Accesses metadata streams for signature and name resolution
//!
//! The implementation mapping system serves as a critical component in method resolution, enabling proper
//! polymorphic behavior and interface implementation validation throughout the .NET type system.
//!
//! # ECMA-335 References
//! - ECMA-335, Partition II, §22.27: `MethodImpl` table specification
//! - ECMA-335, Partition II, §23.2.4: `MethodDefOrRef` coded index encoding
//! - ECMA-335, Partition I, §8.10.4: Interface implementation and method overriding
//!
//! [`SkipMap`]: crossbeam_skiplist::SkipMap
//! [`Arc<boxcar::Vec>`]: std::sync::Arc
use std::sync::Arc;

use crossbeam_skiplist::SkipMap;

use crate::metadata::token::Token;

mod builder;
mod owned;
mod raw;
mod reader;
mod writer;

pub use builder::*;
pub use owned::*;
pub use raw::*;

/// Concurrent map for storing `MethodImpl` entries indexed by [`crate::metadata::token::Token`].
///
/// This thread-safe map enables efficient lookup of method implementation mappings
/// by their associated tokens during metadata processing and method resolution operations.
/// Uses [`crossbeam_skiplist::SkipMap`] for lock-free concurrent access with O(log n) lookup performance.
///
/// # Thread Safety
///
/// [`MethodImplMap`] is [`std::marker::Send`] and [`std::marker::Sync`], enabling safe concurrent access:
/// - Multiple threads can perform lookups simultaneously without blocking
/// - Insert operations are atomic and do not interfere with concurrent reads
/// - Memory ordering guarantees ensure visibility of updates across threads
/// - No additional synchronization required for safe multi-threaded use
pub type MethodImplMap = SkipMap<Token, MethodImplRc>;

/// Thread-safe list for storing collections of `MethodImpl` entries.
///
/// Used for maintaining ordered sequences of method implementation mappings during
/// metadata loading and for iteration over all implementations in a type system.
/// Combines [`boxcar::Vec`] for efficient append operations with [`std::sync::Arc`] for shared ownership.
///
/// # Thread Safety
///
/// [`MethodImplList`] is [`std::marker::Send`] and [`std::marker::Sync`] through [`std::sync::Arc`] wrapping:
/// - Safe to clone and share across multiple threads
/// - Concurrent read access without additional synchronization
/// - Append operations are thread-safe when using appropriate methods
/// - Reference counting ensures memory safety during concurrent access
pub type MethodImplList = Arc<boxcar::Vec<MethodImplRc>>;

/// Reference-counted pointer to a [`MethodImpl`] instance.
///
/// Enables efficient sharing of method implementation mapping data across multiple
/// contexts without duplication, supporting concurrent access patterns in method resolution.
/// Uses [`std::sync::Arc`] for atomic reference counting and safe memory management.
///
/// # Thread Safety
///
/// [`MethodImplRc`] is [`std::marker::Send`] and [`std::marker::Sync`] through [`std::sync::Arc`]:
/// - Safe to clone and pass between threads
/// - Atomic reference counting prevents use-after-free errors
/// - Immutable access to contained [`MethodImpl`] data
/// - Automatic cleanup when last reference is dropped
/// - No risk of data races when accessing implementation mapping information
pub type MethodImplRc = Arc<MethodImpl>;

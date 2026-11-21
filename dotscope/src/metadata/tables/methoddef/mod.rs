//! `MethodDef` table implementation for method definitions and implementations.
//!
//! This module provides complete support for the `MethodDef` metadata table, which defines
//! method implementations within types. The `MethodDef` table is central to the .NET type
//! system, providing method signatures, implementation details, and parameter information
//! essential for method invocation, reflection, and virtual dispatch.
//!
//! # Architecture
//!
//! The module follows a layered architecture for method definition processing:
//! - **Raw Layer**: Binary parsing with unresolved heap indices for memory efficiency
//! - **Loader Layer**: Parallel processing and dependency resolution for owned objects
//! - **Integration Layer**: Type system integration and cross-reference resolution
//! - **API Layer**: Public interfaces for method definition access and manipulation
//!
//! # Module Components
//!
//! - [`crate::metadata::tables::methoddef::raw::MethodDefRaw`] - Raw table structure with unresolved indexes and heap references
//! - [`crate::metadata::loader::tables::MethodDefLoader`] - Internal loader for processing table entries (crate-private)
//! - Method definition containers and concurrent access structures
//! - Parameter resolution and signature parsing utilities
//!
//! # Table Structure (ECMA-335 §22.26)
//! | Column | Type | Description |
//! |--------|------|-------------|
//! | RVA | 4-byte offset | Relative virtual address of method implementation |
//! | `ImplFlags` | 2-byte flags | Method implementation attributes |
//! | Flags | 2-byte flags | Method attributes and access modifiers |
//! | Name | String heap index | Method name identifier |
//! | Signature | Blob heap index | Method signature (calling convention, parameters, return type) |
//! | `ParamList` | Param table index | First parameter in the parameter list |
//!
//! # Method Implementation Types
//!
//! The `MethodDef` table supports various method implementation patterns:
//! - **IL Methods**: Managed code with Common Intermediate Language bytecode
//! - **Native Methods**: Platform-specific native code implementations
//! - **Abstract Methods**: Interface or abstract class method declarations without implementation
//! - **P/Invoke Methods**: Platform invocation service for calling external library functions
//! - **Runtime Methods**: Special methods implemented directly by the runtime system
//! - **Synchronized Methods**: Thread-safe methods with automatic synchronization
//! - **Constructor Methods**: Instance constructors (.ctor) and static constructors (.cctor)
//! - **Property Accessors**: Getter and setter methods for property implementations
//! - **Event Handlers**: Add, remove, and fire methods for event implementations
//!
//! # Method Attributes and Access Control
//!
//! Method flags control visibility, behavior, and implementation characteristics:
//! - **Access Modifiers**: Private, public, protected, internal visibility levels
//! - **Virtual Dispatch**: Virtual, abstract, final, and override method semantics
//! - **Special Methods**: Constructors, property accessors, event handlers, and operators
//! - **Implementation Flags**: Native, managed, synchronized, and security attributes
//! - **Calling Conventions**: Default, vararg, generic, and platform-specific conventions
//! - **Security Attributes**: Declarative security and code access permissions
//!
//! # Parameter Management
//!
//! Methods reference parameter information through the Param table:
//! - **Parameter Metadata**: Names, types, default values, and custom attributes
//! - **Return Type**: Special parameter at sequence 0 for return type information
//! - **Parameter Lists**: Contiguous ranges in the Param table for method parameters
//! - **Optional Parameters**: Default value support for method overloading
//! - **Reference Parameters**: By-reference and output parameter handling
//! - **Generic Parameters**: Type parameter constraints and variance annotations
//!
//! # Virtual Method Dispatch
//!
//! `MethodDef` entries support object-oriented method dispatch patterns:
//! - **Virtual Methods**: Overridable methods with late binding and polymorphism
//! - **Interface Implementations**: Method implementations for interface contracts
//! - **Abstract Methods**: Pure virtual methods requiring derived class implementation
//! - **Method Overriding**: Derived class method replacement with base class compatibility
//! - **Method Hiding**: New methods that hide base class methods with the same signature
//! - **Generic Method Instantiation**: Runtime method instantiation with specific type arguments
//!
//! # Processing Pipeline
//!
//! 1. **Binary Parsing**: Raw MethodDef entries are parsed from metadata tables stream
//! 2. **Dependency Resolution**: Parameter and signature information is resolved
//! 3. **Signature Processing**: Method signatures are parsed from blob heap
//! 4. **Name Resolution**: Method and parameter names are resolved from strings heap
//! 5. **Type Integration**: Methods are integrated into type definitions and hierarchies
//! 6. **Cross-Reference Building**: Virtual method tables and interface implementations are established
//!
//! # Thread Safety
//!
//! All components in this module are designed for safe concurrent access:
//! - Raw parsing operations are stateless and thread-safe
//! - Method definition storage uses concurrent data structures
//! - Parameter resolution is coordinated safely across multiple threads
//! - Type system integration uses atomic operations for consistency
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables::param`] - Parameter table for method parameter information
//! - [`crate::metadata::tables::typedef`] - Type definition table for method ownership
//! - [`crate::metadata::typesystem`] - Type system for method signature resolution
//! - [`crate::metadata::method`] - Method definition containers and access patterns
//!
//! # ECMA-335 References
//!
//! - [ECMA-335 Standard](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/)
//! - Partition II, §22.26: `MethodDef` table specification
//! - Partition II, §23.2.1: Method signature encoding and parsing
//! - Partition I, §8.4.3: Virtual method dispatch and inheritance
//! - Table ID: 0x06
//! - Purpose: Define method implementations within types
mod builder;
mod raw;
mod reader;
mod writer;

pub use builder::*;
pub use raw::*;

//! `StateMachineMethod` table implementation for Portable PDB format
//!
//! This module provides access to `StateMachineMethod` table data, which maps
//! compiler-generated state machine methods (`MoveNext`) back to their original
//! user-written async/await and iterator methods. This mapping is essential for
//! providing a seamless debugging experience with modern C# and VB.NET features.
//!
//! The `StateMachineMethod` table follows the dual-representation pattern used throughout
//! the dotscope library:
//! - [`StateMachineMethodRaw`] for raw binary data with unresolved indices
//! - [`StateMachineMethod`] for processed data with resolved token values
//!
//! # State Machine Context
//!
//! When C# or VB.NET compilers encounter async/await patterns or yield return
//! statements, they generate complex state machine types with `MoveNext` methods
//! that implement the actual logic. The `StateMachineMethod` table provides the
//! crucial mapping that allows debuggers to:
//!
//! - Show the original method name in stack traces
//! - Set breakpoints on the user-written method
//! - Step through async code naturally
//! - Display meaningful variable names and scopes
//!
//! # Usage
//!
//! ```no_run
//! use dotscope::{
//!     metadata::tables::{StateMachineMethodBuilder, StateMachineMethodRaw},
//!     CilAssembly, CilAssemblyView,
//! };
//!
//! // An async method (MethodDef 1) whose state machine's MoveNext is MethodDef 2
//! let mut assembly = CilAssembly::from_path("app.dll")?;
//! StateMachineMethodBuilder::new()
//!     .move_next_method(2)
//!     .kickoff_method(1)
//!     .build(&mut assembly)?;
//!
//! let view = CilAssemblyView::from_mem(assembly.to_memory()?)?;
//! if let Some(mappings) = view.tables().and_then(|t| t.table::<StateMachineMethodRaw>()) {
//!     for mapping in mappings.iter().filter_map(Result::ok) {
//!         println!("MoveNext {} runs kickoff {}", mapping.move_next_method, mapping.kickoff_method);
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # References
//!
//! - [Portable PDB Format - StateMachineMethod Table](https://github.com/dotnet/corefx/blob/master/src/System.Reflection.Metadata/specs/PortablePdb-Metadata.md#statemachinemethod-table-0x36)
//! - [ECMA-335 State Machine Attributes](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)

mod builder;
mod owned;
mod raw;
mod reader;
mod writer;

use std::sync::Arc;

pub use builder::*;
use crossbeam_skiplist::SkipMap;
pub use owned::*;
pub use raw::*;

use crate::metadata::token::Token;

/// A map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`StateMachineMethod`]
///
/// Thread-safe concurrent map using skip list data structure for efficient lookups
/// and insertions. Used to cache resolved state machine method mappings by their metadata tokens.
pub type StateMachineMethodMap = SkipMap<Token, StateMachineMethodRc>;

/// A vector that holds a list of [`StateMachineMethod`] references
///
/// Thread-safe append-only vector for storing state machine method collections. Uses atomic operations
/// for lock-free concurrent access and is optimized for scenarios with frequent reads.
pub type StateMachineMethodList = Arc<boxcar::Vec<StateMachineMethodRc>>;

/// A reference-counted pointer to a [`StateMachineMethod`]
///
/// Provides shared ownership and automatic memory management for state machine method instances.
/// Multiple references can safely point to the same state machine method data across threads.
pub type StateMachineMethodRc = Arc<StateMachineMethod>;

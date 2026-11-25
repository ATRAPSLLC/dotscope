//! `FieldMarshal` metadata table implementation.
//!
//! This module provides structures and utilities for working with the `FieldMarshal` metadata table,
//! which specifies marshalling behavior for fields and parameters when crossing managed/unmanaged
//! boundaries. This is essential for proper interop with native code and COM components.
//!
//! # Overview
//! The `FieldMarshal` table defines how specific fields and parameters should be marshalled:
//! - **P/Invoke marshalling**: Converting parameters for native function calls
//! - **COM interop**: Field and parameter handling for COM objects
//! - **Custom marshalling**: User-defined marshalling behavior through custom marshallers
//! - **Array marshalling**: Specific handling for array types with size and element info
//! - **String marshalling**: Character encoding and memory management strategies
//!
//! # Components
//! - [`crate::metadata::tables::fieldmarshal::raw::FieldMarshalRaw`]: Raw field marshal data read directly from metadata tables
//! - [`crate::metadata::tables::fieldmarshal::owned::FieldMarshal`]: Owned field marshal data with resolved references
//! - [`crate::metadata::loader::tables::FieldMarshalLoader`]: Processes and loads field marshal metadata
//! - [`crate::metadata::tables::fieldmarshal::FieldMarshalMap`]: Thread-safe collection of field marshals indexed by token
//! - [`crate::metadata::tables::fieldmarshal::FieldMarshalList`]: Vector-based collection of field marshals
//! - [`crate::metadata::tables::fieldmarshal::FieldMarshalRc`]: Reference-counted field marshal for shared ownership
//!
//! # Table Structure
//! Each `FieldMarshal` entry contains:
//! - **Parent**: `HasFieldMarshal` coded index (Field or Param reference)
//! - **`NativeType`**: Blob heap index containing marshalling signature
//!
//! # Marshalling Types
//! Common marshalling specifications include:
//! - **`NATIVE_TYPE_BOOLEAN`**: Boolean marshalling (1/4 bytes)
//! - **`NATIVE_TYPE_I1/I2/I4/I8`**: Signed integer marshalling
//! - **`NATIVE_TYPE_U1/U2/U4/U8`**: Unsigned integer marshalling
//! - **`NATIVE_TYPE_R4/R8`**: Floating-point marshalling
//! - **`NATIVE_TYPE_LPSTR/LPWSTR`**: String marshalling with encoding
//! - **`NATIVE_TYPE_ARRAY`**: Array marshalling with element type and size
//! - **`NATIVE_TYPE_CUSTOMMARSHALER`**: Custom marshaller specification
//!
//! # Interop Scenarios
//! - **P/Invoke**: Native function parameter marshalling
//! - **COM Interop**: COM interface field marshalling
//! - **Platform Invoke**: Platform-specific type handling
//! - **Callback Marshalling**: Delegate parameter conversion
//! - **Structure Marshalling**: Complex type layout preservation
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.17 for the complete `FieldMarshal` table specification.

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

/// Thread-safe map of field marshal entries indexed by target token.
///
/// This skip list-based map provides efficient concurrent access to marshalling
/// information, allowing multiple threads to query marshal specifications during
/// interop operations and metadata processing.
pub type FieldMarshalMap = SkipMap<Token, FieldMarshalRc>;

/// Thread-safe vector of field marshal entries.
///
/// This collection provides ordered access to field marshal entries, useful for
/// sequential processing and bulk operations during metadata analysis and interop
/// code generation.
pub type FieldMarshalList = Arc<boxcar::Vec<FieldMarshalRc>>;

/// Reference-counted field marshal entry.
///
/// Provides shared ownership of [`crate::metadata::tables::fieldmarshal::owned::FieldMarshal`] instances, enabling efficient
/// sharing of marshalling data across multiple data structures and threads.
pub type FieldMarshalRc = Arc<FieldMarshal>;

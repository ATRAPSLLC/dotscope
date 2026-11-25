//! Type marshalling for native code invocations and COM interop in .NET assemblies.
//!
//! This module provides constants, types, and logic for parsing and representing native type marshalling
//! as defined in ECMA-335 II.23.2.9 and extended by CoreCLR. It supports marshalling for P/Invoke, COM interop,
//! and other native interop scenarios.
//!
//! # Marshalling Overview
//!
//! .NET marshalling converts managed types to/from native types for interoperability:
//! - **P/Invoke**: Platform Invoke for calling unmanaged functions in DLLs
//! - **COM Interop**: Communication with Component Object Model interfaces
//! - **Windows Runtime**: Integration with WinRT APIs and types
//! - **Custom Marshalling**: User-defined type conversion logic
//!
//! # Supported Native Types
//!
//! The implementation supports all native types from ECMA-335 and CoreCLR:
//! - **Primitive Types**: Integers, floats, booleans, characters
//! - **String Types**: ANSI, Unicode, UTF-8 strings with various encodings
//! - **Array Types**: Fixed arrays, variable arrays, safe arrays
//! - **Pointer Types**: Raw pointers with optional type information
//! - **Interface Types**: COM interfaces (IUnknown, IDispatch, IInspectable)
//! - **Structured Types**: Native structs with packing and size information
//! - **Custom Types**: User-defined marshalling with custom marshalers
//!
//! # Marshalling Descriptors
//!
//! Marshalling information is encoded as binary descriptors containing:
//! 1. **Primary Type**: The main native type to marshal to/from
//! 2. **Parameters**: Size information, parameter indices, and type details
//! 3. **Additional Types**: Secondary types for complex marshalling scenarios
//! 4. **End Marker**: Termination indicator for descriptor boundaries
//!
//! # Thread Safety
//!
//! All types in this module are thread-safe:
//! - **Constants**: Immutable static values
//! - **Enums/Structs**: No internal mutability
//! - **Parsers**: Stateless after construction
//!
//! # Key Components
//!
//! - [`crate::metadata::marshalling::NATIVE_TYPE`] - Constants for all native types used in marshalling
//! - [`crate::metadata::marshalling::VARIANT_TYPE`] - COM variant type constants for safe arrays
//! - [`crate::metadata::marshalling::NativeType`] - Enumeration of all supported native type variants
//! - [`crate::metadata::marshalling::MarshallingInfo`] - Complete marshalling descriptor representation
//! - [`crate::metadata::marshalling::MarshallingParser`] - Parser for binary marshalling descriptors
//! - [`crate::metadata::marshalling::parse_marshalling_descriptor`] - Convenience function for parsing
//! - [`crate::metadata::marshalling::MarshallingEncoder`] - Encoder for binary marshalling descriptors
//! - [`crate::metadata::marshalling::encode_marshalling_descriptor`] - Convenience function for encoding
//!
//! # Examples
//!
//! ## Parsing Simple Types
//!
//! ```rust,no_run
//! use dotscope::metadata::marshalling::{parse_marshalling_descriptor, NativeType, NATIVE_TYPE};
//!
//! # fn main() -> dotscope::Result<()> {
//! // Parse a simple LPSTR marshalling descriptor
//! let descriptor_bytes = &[NATIVE_TYPE::LPSTR, 0x05]; // LPSTR with size param 5
//! let info = parse_marshalling_descriptor(descriptor_bytes)?;
//!
//! match info.primary_type {
//!     NativeType::LPStr { size_param_index: Some(5) } => {
//!         println!("LPSTR with size parameter index 5");
//!     }
//!     _ => unreachable!(),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Parsing Complex Arrays
//!
//! ```rust,no_run
//! use dotscope::metadata::marshalling::{MarshallingParser, NativeType, NATIVE_TYPE};
//!
//! # fn main() -> dotscope::Result<()> {
//! // Parse an array descriptor: Array<I4>[param=3, size=10]
//! let descriptor_bytes = &[
//!     NATIVE_TYPE::ARRAY,
//!     NATIVE_TYPE::I4,
//!     0x03,  // Parameter index 3
//!     0x0A   // Array size 10
//! ];
//!
//! let mut parser = MarshallingParser::new(descriptor_bytes);
//! let native_type = parser.parse_native_type()?;
//!
//! match native_type {
//!     NativeType::Array { element_type, num_param, num_element, .. } => {
//!         println!("Array of {:?}, param: {:?}, size: {:?}",
//!                  element_type, num_param, num_element);
//!     }
//!     _ => unreachable!(),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Working with Custom Marshalers
//!
//! ```rust,no_run
//! use dotscope::metadata::marshalling::NativeType;
//!
//! # fn example(native_type: &NativeType) {
//! match native_type {
//!     NativeType::CustomMarshaler { guid, native_type_name, cookie, type_reference } => {
//!         println!("Custom marshaler: GUID={}, Type={}, Cookie={}, Ref={}",
//!                  guid, native_type_name, cookie, type_reference);
//!     }
//!     _ => { /* Handle other types */ }
//! }
//! # }
//! ```
//!
//! ## Encoding Marshalling Descriptors
//!
//! ```rust,no_run
//! use dotscope::metadata::marshalling::{encode_marshalling_descriptor, NativeType, MarshallingInfo};
//!
//! # fn main() -> dotscope::Result<()> {
//! // Create a marshalling descriptor
//! let info = MarshallingInfo {
//!     primary_type: NativeType::LPStr { size_param_index: Some(5) },
//! };
//!
//! // Encode to binary format
//! let bytes = encode_marshalling_descriptor(&info)?;
//! // Result: [NATIVE_TYPE::LPSTR, 0x05]
//! # Ok(())
//! # }
//! ```

mod encoder;
mod parser;
mod types;

pub use encoder::*;
pub use parser::*;
pub use types::*;
